"""Tools mode: calls the target's tools directly, with no model, and judges the effects.

The supervisor never imports the target. Discovery reads the tools in a supervised worker, the
plan is built from that description and the configuration, and each attack runs in its own
worker through the run engine, with the verdict collector reading the private evidence before
it is deleted. Verdicts, statistics and the gate are the verdict engine's, unchanged.
"""

from __future__ import annotations

import contextlib
import threading
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Final

from gazua.catalog.loader import CatalogEntry
from gazua.catalog.models import Mold
from gazua.catalog.selection import select_molds
from gazua.config.models import GazuaConfig, Limits
from gazua.diagnostics import ConfigError, Diagnostic
from gazua.modes.tools_models import (
    ExitCode,
    ToolsDiagnostic,
    ToolsInventory,
    ToolsOptions,
    ToolsResult,
)
from gazua.modes.tools_plan import ToolsPlan, plan_tools
from gazua.runtime.budget import decimal_text
from gazua.runtime.evidence import EvidenceRedactor, PrivateEvidence
from gazua.runtime.run_models import (
    EXECUTION_STATUSES,
    ExecutionRecord,
    LimitOverrides,
    RunEvent,
    RunSummary,
)
from gazua.verdicts.engine import VerdictCollector
from gazua.verdicts.models import AttackContext, VerdictSummary

EXIT_CLEAN: Final = 0
EXIT_GATED: Final = 1
EXIT_ERROR: Final = 2
NO_TOOL_CAN_RUN: Final = "No tool can run: mark tools safe for test data."
HTTP_REFUSAL: Final = "--tools needs direct tool access; use --agent for HTTP targets."


def discover_tools(
    config: GazuaConfig, project_root: Path, timeout: float | None = None
) -> ToolsInventory:
    """The tools the test module registers when imported, without calling its entrypoint.

    Raises ``ConfigError`` when the module cannot be imported within ``timeout``.
    """
    from gazua.runtime.engine import describe_tools

    document = describe_tools(config, project_root=project_root, timeout=timeout)
    return ToolsInventory.model_validate(document)


def tools_molds(entries: Iterable[CatalogEntry], mold_id: str | None = None) -> list[Mold]:
    """Molds that support tools mode, in catalog order; ``mold_id`` matches exactly.

    An unknown id, or one without tools support, raises ``ConfigError`` before anything runs.
    """
    chosen = [entry.mold for entry in select_molds(entries, "tools")]
    if mold_id is None:
        return chosen
    found = [mold for mold in chosen if mold.id == mold_id]
    if not found:
        raise ConfigError(
            [
                Diagnostic(
                    code="mold_not_found",
                    field="--mold",
                    message="No mold with this id supports tools mode; see gazua run --list.",
                )
            ]
        )
    return found


@dataclass(frozen=True, slots=True)
class ToolsPreview:
    """What the run shows before its first attack."""

    inventory: ToolsInventory
    plan: ToolsPlan
    limits: Limits
    effective_concurrency: int


PreviewCallback = Callable[[ToolsPreview], None]
EventCallback = Callable[[RunEvent], None]
EvidenceCallback = Callable[[ExecutionRecord, PrivateEvidence], None]


def _effective_limits(config: GazuaConfig, options: ToolsOptions) -> Limits:
    from gazua.runtime.engine import effective_limits

    return effective_limits(config, options.overrides)


def _empty_summary(run_id: str, config: GazuaConfig, limits: Limits) -> RunSummary:
    """The summary of a run where nothing could start; it records no execution."""
    estimated = limits.cost_per_run is not None
    return RunSummary(
        schema_version=1,
        run_id=run_id,
        interrupted=False,
        limits=limits,
        requested_concurrency=limits.concurrency,
        effective_concurrency=1 if config.target.reset is not None else limits.concurrency,
        planned=0,
        started=0,
        retries=0,
        counts=dict.fromkeys(EXECUTION_STATUSES, 0),
        cost_source="estimated" if estimated else "unavailable",
        cost_coverage="complete"
        if estimated
        else ("incomplete" if limits.max_cost is not None else "not_applicable"),
        budget_guaranteed=limits.max_cost is not None and estimated,
        reserved_estimate_usd=decimal_text(Decimal(0)) if estimated else None,
        reported_cost_usd=None,
        cleanup="absent",
        operational_errors=[],
        records=[],
    )


def _unique(items: Iterable[str]) -> list[str]:
    found: list[str] = []
    for item in items:
        if item not in found:
            found.append(item)
    return found


def operational_failures(
    summary: RunSummary, verdicts: VerdictSummary, contexts: Sequence[AttackContext]
) -> list[str]:
    """Codes of what went wrong in the infrastructure; each one makes the exit code 2.

    Limits that close admission normally are not failures, and neither is the ceiling reached
    by the mold that exercises it.
    """
    errors = list(verdicts.operational_errors)
    if summary.interrupted:
        errors.append("interrupted")
    ceiling_requests = {
        slot.request_key
        for context in contexts
        if context.signal == "tool_call_ceiling"
        for slot in context.requests
    }
    final: dict[str, int] = {}
    for record in summary.records:
        final[record.request_key] = max(final.get(record.request_key, 0), record.attempt)
    for record in summary.records:
        if record.status in ("crashed", "timed_out", "reset_failed"):
            errors.append(record.reason or record.status)
        elif record.status == "rate_limited" and final[record.request_key] == record.attempt:
            errors.append("rate_limited")
        elif record.status == "killed_at_ceiling" and record.request_key not in ceiling_requests:
            errors.append("unexpected_tool_call_ceiling")
        elif record.status == "cancelled" and record.reason != "max_cost":
            errors.append(record.reason or "cancelled")
    return _unique(errors)


def exit_code_for(failures: Sequence[str], verdicts: VerdictSummary) -> ExitCode:
    """2 on any operational failure, which wins over a gated finding; then 1; else 0."""
    if failures:
        return EXIT_ERROR
    return EXIT_GATED if verdicts.has_gated_findings else EXIT_CLEAN


_RESULT_LIMITS: Final = ("max_runs", "timeout", "max_tool_calls", "max_cost")


def _number(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else repr(float(value))


def reproduction_arguments(
    mold_id: str, config_path: str, overrides: LimitOverrides | None = None
) -> list[str]:
    """The command that runs every unit of this mold again, as an argument list.

    Limit overrides that can change a result are kept; concurrency cannot, so it is left out.
    """
    arguments = ["gazua", "run", "--tools", "--config", config_path, "--mold", mold_id]
    if overrides is not None:
        for name in _RESULT_LIMITS:
            value = getattr(overrides, name)
            if value is not None:
                arguments.extend([f"--{name.replace('_', '-')}", _number(value)])
    return arguments


def run_tools(
    config: GazuaConfig,
    catalog: Iterable[CatalogEntry],
    options: ToolsOptions,
    project_root: Path,
    *,
    inventory: ToolsInventory | None = None,
    on_preview: PreviewCallback | None = None,
    on_event: EventCallback | None = None,
    cancel: threading.Event | None = None,
    on_evidence: EvidenceCallback | None = None,
    evidence_redactor: EvidenceRedactor | None = None,
    storage_available: bool = True,
) -> ToolsResult:
    """Runs the tools molds of the catalog against the project and returns the native results.

    Configuration problems raise ``ConfigError`` before the target is imported. Everything
    found after that, including a run where no tool can be called, is in the result and its
    exit code. ``inventory`` replaces discovery, for consumers that already have one.

    ``on_evidence`` sees each attempt's private evidence after the verdict collector; its
    failure never changes a verdict. ``evidence_redactor`` replaces the engine's default
    redaction of persisted evidence. Without ``storage_available`` nothing is executed and the
    whole plan is not tested, with ``report_storage_unavailable``.
    """
    from gazua.runtime.engine import STORAGE_UNAVAILABLE, execute_plan, new_run_id, prepare_run
    from gazua.runtime.evidence import EvidencePathError

    molds = tools_molds(catalog, options.mold)
    limits = _effective_limits(config, options)
    found = (
        inventory
        if inventory is not None
        else discover_tools(config, project_root, timeout=limits.timeout)
    )
    plan = plan_tools(molds, config, found, language=options.language)
    contexts = plan.contexts
    diagnostics = list(plan.diagnostics)
    blocked: list[str] = []
    if not found.runnable:
        blocked.append("no_runnable_tool")
        diagnostics.append(ToolsDiagnostic(code="no_runnable_tool"))
        if config.tools and not any(tool.registered for tool in found.tools):
            diagnostics.append(ToolsDiagnostic(code="no_tools_registered"))
    requests = plan.requests if not blocked else []
    unexecuted: str | None = None
    summary: RunSummary | None = None
    if requests and storage_available:
        run_plan = prepare_run(config, requests, options.overrides, project_root=project_root)
        if on_preview is not None:
            on_preview(ToolsPreview(found, plan, run_plan.limits, run_plan.effective_concurrency))
        collector = VerdictCollector.for_plan(contexts, run_plan)

        def collect(record: ExecutionRecord, evidence: PrivateEvidence) -> None:
            collector(record, evidence)
            if on_evidence is not None:
                with contextlib.suppress(Exception):
                    on_evidence(record, evidence)

        try:
            summary = execute_plan(
                run_plan,
                on_event,
                on_evidence=collect,
                cancel=cancel,
                evidence_redactor=evidence_redactor,
            )
        except (OSError, EvidencePathError):
            unexecuted = STORAGE_UNAVAILABLE
            summary = _empty_summary(run_plan.run_id, config, limits)
        verdicts = collector.finalize(summary, unexecuted_reason=unexecuted)
    else:
        summary = _empty_summary(new_run_id(), config, limits)
        if on_preview is not None:
            on_preview(ToolsPreview(found, plan, limits, summary.effective_concurrency))
        collector = VerdictCollector(contexts, config, max_tool_calls=limits.max_tool_calls)
        if requests:
            unexecuted = STORAGE_UNAVAILABLE
        verdicts = collector.finalize(summary, unexecuted_reason=unexecuted)
    failures = [*blocked, *operational_failures(summary, verdicts, contexts)]
    if unexecuted is not None and unexecuted not in failures:
        failures.append(unexecuted)
    diagnostics.extend(
        ToolsDiagnostic(code=code) for code in failures if code != "no_runnable_tool"
    )
    return ToolsResult(
        run_id=summary.run_id,
        inventory=found,
        contexts=contexts,
        engine=summary,
        verdicts=verdicts,
        diagnostics=diagnostics,
        executed=bool(requests) and unexecuted is None,
        reproduction={
            context.attack_key: reproduction_arguments(
                context.mold.id, options.config_path, options.overrides
            )
            for context in contexts
        },
        exit_code=exit_code_for(failures, verdicts),
    )
