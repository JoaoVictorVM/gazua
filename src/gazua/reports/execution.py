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
from typing import Any, Final, Literal

from gazua.config.models import GazuaConfig
from gazua.reports.models import RunDocument

STORAGE_UNAVAILABLE: Final = (
    "Cannot write to .gazua/ in the project folder: no attack was run. The full summary follows."
)
INTERRUPTED_BEFORE_ATTACKS: Final = "Interrupted before any attack ran."

Mode = Literal["tools", "agent"]


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
) -> ExecutionOutcome:
    """Runs the mode, then shows and saves its reports.

    Configuration problems raise ``ConfigError`` before the target is imported, as the modes
    do. A failure to write the reports keeps the previous ones and returns exit code 2.
    Setting ``cancel`` stops the run as Ctrl+C does.
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
    created_at = _timestamp()
    common: dict[str, Any] = {
        "on_event": show_progress,
        "on_evidence": capture,
        "evidence_redactor": EngineRedaction(redactor),
        "storage_available": ready,
        "cancel": cancel,
    }
    try:
        if mode == "tools":
            from gazua.modes.tools import ToolsPreview, run_tools
            from gazua.modes.tools_presentation import inventory_lines

            def show_tools_preview(preview: ToolsPreview) -> None:
                for line in inventory_lines(preview):
                    output.say(line)

            result: Any = run_tools(
                config, entries, options, project_root, on_preview=show_tools_preview, **common
            )
        else:
            from gazua.modes.agent import run_agent
            from gazua.modes.agent_models import AgentPreview
            from gazua.modes.agent_presentation import preview_lines

            def show_agent_preview(preview: AgentPreview) -> None:
                output.lines(preview_lines(preview))

            result = run_agent(
                config, entries, options, project_root, on_preview=show_agent_preview, **common
            )
    except KeyboardInterrupt:
        output.warn(INTERRUPTED_BEFORE_ATTACKS)
        return ExecutionOutcome(exit_code=2, interrupted=True)
    document = build_run_document(
        run_id=result.run_id,
        created_at=created_at,
        target_ref=config.entrypoint or "",
        mode=mode,
        language=options.language,
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
    "installed_version",
]
