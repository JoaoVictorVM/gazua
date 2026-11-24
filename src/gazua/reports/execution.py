"""Runs one tools or agent mode and publishes its reports, for the CLI and the demo alike.

The caller loads the configuration and the catalog, holds the lifecycle lock and decides how
lines are shown. This module runs the mode with evidence capture and redaction, builds the run
document, renders and saves it, and returns the document, the paths and the exit code. It never
takes the lock itself, so a coordinator that already holds it can run several modes in turn.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Literal

from gazua.baseline.selection import target_ref
from gazua.config.models import GazuaConfig
from gazua.reports.models import RunDocument

if TYPE_CHECKING:
    from gazua.baseline.models import ScenarioReference, VerificationResult
    from gazua.baseline.storage import LoadedBaseline

STORAGE_UNAVAILABLE: Final = (
    "Cannot write to .gazua/ in the project folder: no attack was run. The full summary follows."
)
INTERRUPTED_BEFORE_ATTACKS: Final = "Interrupted before any attack ran."

Mode = Literal["tools", "agent"]
Runner = Callable[[dict[str, Any]], Any]
Decider = Callable[[Any], "VerificationResult"]


@dataclass(frozen=True, slots=True)
class ReportOutput:
    """Where the service writes: plain lines, terminal-cleaned lines and warnings."""

    say: Callable[[str], None]
    lines: Callable[[Sequence[str]], None]
    warn: Callable[[str], None]


@dataclass(frozen=True, slots=True)
class ExecutionOutcome:
    """One mode's run: its native result, its document and where the reports were saved.

    ``paths`` holds the latest set and the archive, relative to the project root, and is empty
    when nothing was saved. ``interrupted`` means the run stopped before any attack ran.
    """

    exit_code: Literal[0, 1, 2]
    native: Any = None
    document: RunDocument | None = None
    paths: dict[str, str] = field(default_factory=dict[str, str])
    interrupted: bool = False


def installed_version() -> str | None:
    try:
        return version("gazua")
    except PackageNotFoundError:
        return None


def _timestamp() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def execute_mode(
    mode: Mode,
    config: GazuaConfig,
    entries: Any,
    options: Any,
    project_root: Path,
    output: ReportOutput,
    *,
    locked: bool,
    no_redact: bool = False,
    model: str | None = None,
    target_version: str | None = None,
    cancel: threading.Event | None = None,
    demo: bool = False,
    baseline: LoadedBaseline | None = None,
) -> ExecutionOutcome:
    """Runs the mode, then shows and saves its reports.

    Configuration problems raise ``ConfigError`` before the target is imported, as the modes
    do. A failure to write the reports keeps the previous ones and returns exit code 2.
    Setting ``cancel`` stops the run as Ctrl+C does. With ``baseline`` the findings are
    compared with it and the exit code is the effective one; the baseline is only read.
    """

    def run(common: dict[str, Any]) -> Any:
        if mode == "tools":
            from gazua.modes.tools import ToolsPreview, run_tools
            from gazua.modes.tools_presentation import inventory_lines

            def show_tools_preview(preview: ToolsPreview) -> None:
                for line in inventory_lines(preview):
                    output.say(line)

            return run_tools(
                config, entries, options, project_root, on_preview=show_tools_preview, **common
            )
        from gazua.modes.agent import run_agent
        from gazua.modes.agent_models import AgentPreview
        from gazua.modes.agent_presentation import preview_lines

        def show_agent_preview(preview: AgentPreview) -> None:
            output.lines(preview_lines(preview))

        return run_agent(
            config, entries, options, project_root, on_preview=show_agent_preview, **common
        )

    return execute_runner(
        mode,
        run,
        config,
        options.language,
        project_root,
        output,
        locked=locked,
        no_redact=no_redact,
        model=model,
        target_version=target_version,
        cancel=cancel,
        demo=demo,
        baseline=baseline,
    )


class DeliveryCounter:
    """Counts the description deliveries each MCP attempt's private channel recorded."""

    def __init__(self) -> None:
        self.seen: dict[str, tuple[str, int, bool, str | None]] = {}

    def __call__(self, record: Any, evidence: Any) -> None:
        channel = getattr(evidence, "deliveries", None)
        if channel is None:
            return
        delivered = sum(1 for item in channel.deliveries if item.delivered)
        reasons = [item.reason for item in channel.deliveries if item.reason is not None]
        reason = None if channel.complete else "mcp_evidence_invalid"
        if reason is None and reasons:
            reason = "injection_not_delivered"
        self.seen[record.request_key] = (record.execution_id, delivered, channel.complete, reason)


def mcp_provenance(result: Any, deliveries: DeliveryCounter) -> Any:
    """The MCP part of a run document: the snapshot's hash and names, what changed, coverage.

    A tool counts as changed when an attempt that depends on it stopped because its
    definition differed from the approved snapshot.
    """
    from gazua.reports.models import McpDeliveryCoverage, McpProvenance

    snapshot = getattr(getattr(result, "inventory", None), "mcp", None)
    if snapshot is None:
        return None
    by_request = {
        slot.request_key: context for context in result.contexts for slot in context.requests
    }
    changed: set[str] = set()
    for record in result.engine.records:
        context = by_request.get(record.request_key)
        if record.reason == "mcp_tool_changed" and context is not None and context.tool_name:
            changed.add(context.tool_name)
    coverage: list[McpDeliveryCoverage] = []
    for key, (execution_id, delivered, complete, reason) in deliveries.seen.items():
        context = by_request.get(key)
        if context is None or context.mold.entry != "mcp_tool_description":
            continue
        coverage.append(
            McpDeliveryCoverage(
                attack_key=context.attack_key,
                execution_id=execution_id,
                expected_turns=len(context.mold.text.en),
                delivered_turns=min(delivered, len(context.mold.text.en)),
                complete=complete,
                reason=reason,
            )
        )
    return McpProvenance(
        protocol_version=snapshot.protocol_version,
        inventory_hash=snapshot.digest,
        tools=[tool.name for tool in snapshot.tools],
        changed_tools=sorted(changed),
        deliveries=coverage,
    )


class TraceCounter:
    """Counts each attempt's trace channel; spans themselves are never kept here."""

    def __init__(self) -> None:
        self.seen: dict[str, tuple[bool, int, str | None]] = {}
        self._lock = threading.Lock()

    def __call__(self, record: Any, evidence: Any) -> None:
        traces = getattr(evidence, "traces", None)
        with self._lock:
            if traces is None:
                self.seen[record.execution_id] = (False, 0, "otel_evidence_missing")
            else:
                self.seen[record.execution_id] = (traces.complete, traces.accepted, traces.reason)


def http_provenance(config: GazuaConfig, counter: TraceCounter) -> Any:
    """The HTTP part of a run document: the origin and how far the spans covered the run."""
    from gazua.http.models import parse_endpoint
    from gazua.reports.models import HttpProvenance, HttpTraceSummary

    if config.http is None:
        return None
    origin = parse_endpoint(config.http.endpoint).origin
    if config.traces is None:
        summary = HttpTraceSummary(
            enabled=False, coverage="not_applicable", accepted_tool_spans=0, reason="traces_off"
        )
        return HttpProvenance(origin=origin, traces=summary)
    seen = list(counter.seen.values())
    complete = sum(1 for item in seen if item[0])
    reasons = [item[2] for item in seen if item[2] is not None]
    if seen and complete == len(seen):
        coverage = "complete"
    elif complete:
        coverage = "partial"
    else:
        coverage = "none"
    if not seen:
        reasons.append("no_attempt_executed")
    summary = HttpTraceSummary(
        enabled=True,
        coverage=coverage,
        accepted_tool_spans=sum(item[1] for item in seen),
        reason=reasons[0] if reasons else None,
    )
    return HttpProvenance(origin=origin, traces=summary)


def execute_runner(
    mode: Mode,
    runner: Runner,
    config: GazuaConfig,
    language: Literal["en", "pt"],
    project_root: Path,
    output: ReportOutput,
    *,
    locked: bool,
    no_redact: bool = False,
    model: str | None = None,
    target_version: str | None = None,
    cancel: threading.Event | None = None,
    demo: bool = False,
    baseline: LoadedBaseline | None = None,
    decide: Decider | None = None,
    references: dict[str, ScenarioReference] | None = None,
) -> ExecutionOutcome:
    """Runs ``runner`` with capture and redaction, then builds, shows and saves the reports.

    ``runner`` receives the keyword arguments every mode takes (events, evidence, redaction,
    storage and cancel) and returns the mode's native result. ``decide`` turns that result
    into the verification decision the document keeps.
    """
    from gazua.reports.builder import build_run_document
    from gazua.reports.capture import ReportEvidenceCollector
    from gazua.reports.redaction import EngineRedaction, ReportRedactionPolicy, ReportRedactor
    from gazua.reports.rendering import render_report, terminal_lines
    from gazua.reports.storage import StorageError, save_run, storage_ready
    from gazua.runtime.run_models import Progress, RunEvent

    def show_progress(event: RunEvent) -> None:
        progress = getattr(event, "progress", None)
        if event.kind == "execution_finished" and isinstance(progress, Progress):
            output.say(progress.text)

    ready = locked and storage_ready(project_root)
    if not ready:
        output.warn(STORAGE_UNAVAILABLE)
    redactor = ReportRedactor(ReportRedactionPolicy.from_config(config, no_redact=no_redact))
    capture = ReportEvidenceCollector(redactor)
    deliveries = DeliveryCounter()
    traces = TraceCounter()

    def collect(record: Any, evidence: Any) -> None:
        capture(record, evidence)
        if config.mcp is not None:
            deliveries(record, evidence)
        if config.traces is not None:
            traces(record, evidence)

    created_at = _timestamp()
    common: dict[str, Any] = {
        "on_event": show_progress,
        "on_evidence": collect,
        "evidence_redactor": EngineRedaction(redactor),
        "storage_available": ready,
        "cancel": cancel,
    }
    try:
        result: Any = runner(common)
    except KeyboardInterrupt:
        output.warn(INTERRUPTED_BEFORE_ATTACKS)
        return ExecutionOutcome(exit_code=2, interrupted=True)
    document = build_run_document(
        run_id=result.run_id,
        created_at=created_at,
        target_ref=target_ref(config),
        mode=mode,
        language=language,
        engine=result.engine,
        verdicts=result.verdicts,
        contexts=result.contexts,
        reproduction=result.reproduction,
        treatment=redactor,
        exit_code=result.exit_code,
        config=config,
        excerpts=capture,
        gazua_version=installed_version(),
        target_version=target_version,
        model=model,
        diagnostics=capture.diagnostics(),
        legitimate_use=getattr(result, "legitimate_use", None),
        demo=demo,
        baseline=None if baseline is None else baseline.document,
        baseline_digest=None if baseline is None else baseline.digest,
        verification=None if decide is None else decide(result),
        references=references,
        mcp=mcp_provenance(result, deliveries) if config.mcp is not None else None,
        http=http_provenance(config, traces),
        typescript=getattr(getattr(result, "inventory", None), "typescript", None),
    )
    output.lines(terminal_lines(document))
    if mode == "tools":
        from gazua.modes.tools_presentation import diagnostic_lines

        output.lines(diagnostic_lines(result))
    if not ready:
        return ExecutionOutcome(exit_code=2, native=result, document=document)
    try:
        html, markdown = render_report(document)
        saved = save_run(project_root, document, html, markdown)
    except StorageError as error:
        output.warn(
            f"The reports could not be written ({error.code.replace('_', ' ')}); the summary "
            "above is complete and the previous reports were kept."
        )
        return ExecutionOutcome(exit_code=2, native=result, document=document)
    for diagnostic in saved.diagnostics:
        output.warn(f"Retention: {diagnostic.code.replace('_', ' ')}.")
    paths = saved.paths
    output.say(f"Reports: {paths['html']}, {paths['markdown']}, {paths['json']}")
    output.say(f"Archived as {paths['archive']}; the last {saved.retained_runs} runs are kept.")
    code: Literal[0, 1, 2] = max(document.report_exit_code, saved.exit_code)
    return ExecutionOutcome(exit_code=code, native=result, document=document, paths=dict(paths))


__all__ = [
    "INTERRUPTED_BEFORE_ATTACKS",
    "STORAGE_UNAVAILABLE",
    "ExecutionOutcome",
    "ReportOutput",
    "execute_mode",
    "execute_runner",
    "installed_version",
]
