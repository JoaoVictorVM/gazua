"""Agent mode: sends the attacks to the project's own agent and judges the effects in code.

The project's entrypoint calls its real model with its own configuration and credential; Gazua
never asks for, reads or stores a key. The supervisor never imports the target: tools are
discovered in a supervised worker, every attempt runs in its own worker through the run engine,
and the verdict collector reads the private evidence before it is deleted. Verdicts, statistics
and the gate are the verdict engine's, unchanged.
"""

from __future__ import annotations

import contextlib
import threading
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Final

from gazua.catalog.loader import CatalogEntry
from gazua.catalog.models import Mold
from gazua.config.models import GazuaConfig, Limits
from gazua.diagnostics import ConfigError, Diagnostic
from gazua.modes.agent_models import (
    AgentDiagnostic,
    AgentOptions,
    AgentPreview,
    AgentResult,
    empty_legitimate_use,
)
from gazua.modes.agent_plan import AgentPlan, agent_molds, plan_agent, quick_selection
from gazua.modes.tools import (
    discover_tools,
    empty_summary,
    exit_code_for,
    operational_failures,
)
from gazua.modes.tools_models import ToolsInventory
from gazua.runtime.evidence import EvidenceRedactor, PrivateEvidence
from gazua.runtime.run_models import (
    IDENTICAL_FAILURE_LIMIT,
    MAX_RETRIES,
    ExecutionRecord,
    LimitOverrides,
    RunEvent,
    RunSummary,
    StopPolicy,
)
from gazua.verdicts.engine import VerdictCollector

AUTHENTICATION_MESSAGE: Final = "The agent could not authenticate; Gazua does not manage its key"
AGENT_WARNING: Final = (
    "Agent mode sends attack text to your model provider through your agent and may cost "
    "money. It is meant for nightly and pre-release runs, not for every pull request."
)
_RESULT_LIMITS: Final = ("max_runs", "timeout", "max_tool_calls", "max_cost")

PreviewCallback = Callable[[AgentPreview], None]
EventCallback = Callable[[RunEvent], None]
EvidenceCallback = Callable[[ExecutionRecord, PrivateEvidence], None]


def check_entries(config: GazuaConfig, inventory: ToolsInventory) -> None:
    """Every declared entry tool must be registered by the test module, before any model call.

    A missing tool would leave the entry unreachable while looking declared, so it is a
    configuration error; it is never replaced by another tool.
    """
    problems: list[Diagnostic] = []
    for entry in ("tool_result", "rag_document", "poisoned_memory"):
        declared = config.agent_entries.get(entry)
        if declared is None:
            continue
        found = inventory.get(declared.tool)
        if found is None or not found.registered or found.ambiguous:
            problems.append(
                Diagnostic(
                    code="agent_entry_tool_not_registered",
                    field=f"agent_entries.{entry}.tool",
                    message="The test module does not register this tool through gazua.wrap "
                    "or @gazua.tool, so the entry cannot be reached.",
                )
            )
    if problems:
        raise ConfigError(problems)


def select_agent_molds(entries: Iterable[CatalogEntry], options: AgentOptions) -> list[Mold]:
    """The exact mold when one is named, the quick selection with ``quick``, else every one."""
    molds = agent_molds(entries, options.mold)
    if options.quick and options.mold is None:
        return quick_selection(molds)
    return molds


def _number(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else repr(float(value))


def reproduction_arguments(
    mold_id: str,
    config_path: str,
    overrides: LimitOverrides | None = None,
    *,
    quick: bool = False,
    language: str = "en",
) -> list[str]:
    """The command that runs every scenario of this mold again, as an argument list.

    The language and limits that can change a result are kept; concurrency cannot, so it is
    left out. The agent's model may answer differently on another run.
    """
    arguments = ["gazua", "run", "--agent", "--config", config_path, "--mold", mold_id]
    if quick:
        arguments.append("--quick")
    if language != "en":
        arguments.extend(["--language", language])
    if overrides is not None:
        for name in _RESULT_LIMITS:
            value = getattr(overrides, name)
            if value is not None:
                arguments.extend([f"--{name.replace('_', '-')}", _number(value)])
    return arguments


def build_preview(
    plan: AgentPlan,
    inventory: ToolsInventory,
    limits: Limits,
    *,
    effective_concurrency: int,
    cost_source: str,
) -> AgentPreview:
    attack_slots = len(plan.attack_requests)
    return AgentPreview.model_validate(
        {
            "selection": plan.selection.model_dump(),
            "inventory": inventory.model_dump(),
            "scenarios": len(plan.scenarios),
            "executable_scenarios": plan.executable_scenarios,
            "attack_slots": attack_slots,
            "impeded_slots": plan.impeded_slots,
            "legitimate_tasks": len(plan.legitimate),
            "planned_executions": attack_slots + len(plan.legitimate),
            "max_runs": limits.max_runs,
            "max_retries": MAX_RETRIES,
            "requested_concurrency": limits.concurrency,
            "effective_concurrency": effective_concurrency,
            "cost_source": cost_source,
            "max_cost": limits.max_cost,
            "cost_per_run": limits.cost_per_run,
        }
    )


def stop_failures(summary: RunSummary) -> list[str]:
    return [] if summary.stop_reason is None else [summary.stop_reason]


def run_agent(
    config: GazuaConfig,
    catalog: Iterable[CatalogEntry],
    options: AgentOptions,
    project_root: Path,
    *,
    inventory: ToolsInventory | None = None,
    on_preview: PreviewCallback | None = None,
    on_event: EventCallback | None = None,
    cancel: threading.Event | None = None,
    on_evidence: EvidenceCallback | None = None,
    evidence_redactor: EvidenceRedactor | None = None,
    storage_available: bool = True,
) -> AgentResult:
    """Runs the agent molds of the catalog against the project and returns the native results.

    Configuration problems, an unknown mold and an unregistered entry tool raise
    ``ConfigError`` before the agent is called. Everything found after that is in the result
    and its exit code. ``inventory`` replaces discovery. ``on_preview`` runs before the first
    call to the agent. ``on_evidence`` sees each attempt's private evidence after the
    collectors; its failure never changes a verdict.
    """
    from gazua.runtime.engine import (
        STORAGE_UNAVAILABLE,
        effective_limits,
        execute_plan,
        new_run_id,
        prepare_run,
    )
    from gazua.runtime.evidence import EvidencePathError

    molds = select_agent_molds(catalog, options)
    limits = effective_limits(config, options.overrides)
    if config.entrypoint is None:
        raise ConfigError(
            [
                Diagnostic(
                    code="entrypoint_missing",
                    field="entrypoint",
                    message="Agent mode sends messages to the entrypoint; declare entrypoint.",
                )
            ]
        )
    found = (
        inventory
        if inventory is not None
        else discover_tools(config, project_root, timeout=limits.timeout)
    )
    check_entries(config, found)
    plan = plan_agent(
        molds,
        config,
        found,
        language=options.language,
        repetitions=options.effective_repetitions,
        quick=options.quick,
        exact_mold=options.mold,
    )
    contexts = plan.contexts
    diagnostics = list(plan.diagnostics)
    requests = plan.attack_requests
    unexecuted: str | None = None
    if requests and storage_available:
        run_plan = prepare_run(
            config, requests, options.overrides, project_root=project_root, stop_policy=StopPolicy()
        )
        if on_preview is not None:
            on_preview(
                build_preview(
                    plan,
                    found,
                    run_plan.limits,
                    effective_concurrency=run_plan.effective_concurrency,
                    cost_source=run_plan.cost_source,
                )
            )
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
            summary = empty_summary(run_plan.run_id, config, limits)
        verdicts = collector.finalize(summary, unexecuted_reason=unexecuted)
    else:
        summary = empty_summary(new_run_id(), config, limits)
        if on_preview is not None:
            on_preview(
                build_preview(
                    plan,
                    found,
                    limits,
                    effective_concurrency=summary.effective_concurrency,
                    cost_source=summary.cost_source,
                )
            )
        collector = VerdictCollector(contexts, config, max_tool_calls=limits.max_tool_calls)
        if requests:
            unexecuted = STORAGE_UNAVAILABLE
        verdicts = collector.finalize(summary, unexecuted_reason=unexecuted)
    failures = [*operational_failures(summary, verdicts, contexts), *stop_failures(summary)]
    if unexecuted is not None:
        failures.append(unexecuted)
    unique: list[str] = []
    for code in failures:
        if code not in unique:
            unique.append(code)
    diagnostics.extend(AgentDiagnostic(code=code) for code in unique)
    return AgentResult(
        run_id=summary.run_id,
        inventory=found,
        selection=plan.selection,
        contexts=contexts,
        engine=summary,
        verdicts=verdicts,
        legitimate_use=empty_legitimate_use(),
        diagnostics=diagnostics,
        executed=bool(requests) and unexecuted is None,
        reproduction={
            context.attack_key: reproduction_arguments(
                context.mold.id,
                options.config_path,
                options.overrides,
                quick=options.quick,
                language=options.language,
            )
            for context in contexts
        },
        exit_code=exit_code_for(unique, verdicts),
    )


def stop_message(summary: RunSummary) -> str | None:
    """The fixed sentence that explains why the run stopped early, without target text."""
    reason, error = summary.stop_reason, summary.stop_error
    if reason is None:
        return None
    if reason == "agent_authentication_failed":
        return AUTHENTICATION_MESSAGE
    if reason == "persistent_rate_limit":
        return (
            "The agent kept reporting rate limits (429); the run stopped and the remaining "
            "executions are not tested."
        )
    shared = "unknown error"
    if error is not None:
        shared = error.code.replace("_", " ")
        if error.error_type is not None:
            shared += f" ({error.error_type})"
    return (
        f"The run stopped after {IDENTICAL_FAILURE_LIMIT} consecutive identical failures; the "
        f"remaining executions are not tested. Shared error: {shared}."
    )


__all__ = [
    "AGENT_WARNING",
    "AUTHENTICATION_MESSAGE",
    "build_preview",
    "check_entries",
    "reproduction_arguments",
    "run_agent",
    "select_agent_molds",
    "stop_message",
]
