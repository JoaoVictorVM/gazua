"""Runs ``gazua verify``: the plan through the existing engine, the decision, the transition.

The caller holds the lifecycle lock for the whole cycle. The report, with the decision it
proposes, is saved first; only then is the baseline replaced, atomically and only if it still
holds the bytes read at the start. A failure between the two writes leaves the evidence and the
previous state. An interruption changes nothing. No retry, legitimate task or earlier run ever
counts as one of the 20 repetitions.
"""

from __future__ import annotations

import contextlib
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from gazua.baseline.models import (
    VERIFY_REPETITIONS,
    BaselineDocument,
    BaselineEntry,
    VerificationResult,
    VerificationSample,
    ordered_references,
)
from gazua.baseline.plan import VerificationPlan
from gazua.baseline.storage import (
    BaselineError,
    LoadedBaseline,
    package_version,
    parse_baseline,
    write_baseline,
)
from gazua.config.models import GazuaConfig
from gazua.runtime.run_models import LimitOverrides, RunSummary
from gazua.verdicts.models import AttackContext, VerdictSummary

FAILED_CLEANUP = ("failed", "aborted", "timed_out")


@dataclass(frozen=True, slots=True)
class VerificationRun:
    """The native results of a verification, shaped as the report service reads them."""

    run_id: str
    contexts: list[AttackContext]
    engine: RunSummary
    verdicts: VerdictSummary
    failures: list[str]
    reproduction: dict[str, list[str]]
    exit_code: Literal[0, 1, 2]
    legitimate_use: None = None
    inventory: Any = None
    diagnostics: list[Any] = field(default_factory=list[Any])


MCP_PROVENANCE_CHANGED = "mcp_provenance_changed"
MCP_PROVENANCE_MISSING = "mcp_provenance_missing"


def mcp_provenance_problem(project_root: Path, finding_id: str, inventory: Any) -> str | None:
    """Why an MCP finding cannot be closed by this replay; None when the snapshot matches.

    The newest kept run that holds the finding gives the inventory it was found against. A
    different hash means the server's tools changed, so a quiet replay proves nothing about the
    original finding. Without such a run, or with a Python run, the provenance is unknown.
    """
    from gazua.reports.storage import RunLoadError, load_run_document

    current = getattr(getattr(inventory, "mcp", None), "digest", None)
    folder = project_root / ".gazua" / "runs"
    paths = sorted(folder.glob("*/run.json"), reverse=True) if folder.is_dir() else []
    for path in paths:
        try:
            document = load_run_document(path)
        except (RunLoadError, OSError, ValueError):
            continue
        if not any(item.id == finding_id for item in document.findings):
            continue
        if document.mcp is None or current is None:
            return MCP_PROVENANCE_MISSING
        return None if document.mcp.inventory_hash == current else MCP_PROVENANCE_CHANGED
    return MCP_PROVENANCE_MISSING


HTTP_PROVENANCE_CHANGED = "http_provenance_changed"
HTTP_PROVENANCE_MISSING = "http_provenance_missing"


def http_provenance_problem(project_root: Path, finding_id: str, origin: str) -> str | None:
    """Why an HTTP finding cannot be closed by this replay; None when adapter and origin match.

    The newest kept run that holds the finding must have reached the same origin over HTTP. A
    finding recorded through another adapter, or a run no longer kept, never closes here.
    """
    from gazua.reports.storage import RunLoadError, load_run_document

    folder = project_root / ".gazua" / "runs"
    paths = sorted(folder.glob("*/run.json"), reverse=True) if folder.is_dir() else []
    for path in paths:
        try:
            document = load_run_document(path)
        except (RunLoadError, OSError, ValueError):
            continue
        if not any(item.id == finding_id for item in document.findings):
            continue
        if document.target_adapter != "http" or document.http is None:
            return HTTP_PROVENANCE_CHANGED
        return None if document.http.origin == origin else HTTP_PROVENANCE_CHANGED
    return HTTP_PROVENANCE_MISSING


TYPESCRIPT_PROVENANCE_CHANGED = "typescript_provenance_changed"
TYPESCRIPT_PROVENANCE_MISSING = "typescript_provenance_missing"


def typescript_provenance_problem(
    project_root: Path, finding_id: str, inventory: Any
) -> str | None:
    """Why a TypeScript finding cannot be closed by this replay; None when the target matches.

    The newest kept run that holds the finding must have reached a TypeScript target through
    the same protocol, with the same compiled module and the same npm package line. Another
    adapter, another module or a run no longer kept never closes the finding here.
    """
    from gazua.reports.storage import RunLoadError, load_run_document
    from gazua.typescript.executor import base_version

    current = getattr(inventory, "typescript", None)
    folder = project_root / ".gazua" / "runs"
    paths = sorted(folder.glob("*/run.json"), reverse=True) if folder.is_dir() else []
    for path in paths:
        try:
            document = load_run_document(path)
        except (RunLoadError, OSError, ValueError):
            continue
        if not any(item.id == finding_id for item in document.findings):
            continue
        recorded = document.typescript
        if document.target_adapter != "typescript" or recorded is None or current is None:
            return TYPESCRIPT_PROVENANCE_CHANGED
        same = (
            recorded.protocol_version == current.protocol_version
            and recorded.module_sha256 == current.module_sha256
            and base_version(recorded.sdk_version) == base_version(current.sdk_version)
        )
        return None if same else TYPESCRIPT_PROVENANCE_CHANGED
    return TYPESCRIPT_PROVENANCE_MISSING


def reproduction_arguments(
    finding_id: str, config_path: str, mode: str, overrides: LimitOverrides | None
) -> list[str]:
    """The command that runs this verification again; Gazua never runs it from a report."""
    arguments = ["gazua", "verify", finding_id, "--config", config_path, "--mode", mode]
    if overrides is not None:
        for name in ("max_runs", "timeout", "max_tool_calls", "max_cost"):
            value = getattr(overrides, name)
            if value is not None:
                shown = str(int(value)) if float(value).is_integer() else repr(float(value))
                arguments.extend([f"--{name.replace('_', '-')}", shown])
    return arguments


def execute(
    plan: VerificationPlan,
    config: GazuaConfig,
    overrides: LimitOverrides,
    project_root: Path,
    config_path: str,
    common: dict[str, Any],
    on_preview: Callable[[Any], None] | None = None,
    *,
    inventory: Any = None,
    extra_failures: Sequence[str] = (),
) -> VerificationRun:
    """Runs every slot under one plan and one budget, with the verdict collector.

    ``extra_failures`` are problems found before the run, such as an MCP server whose tools
    changed since the finding was recorded; each one keeps the finding from closing.
    """
    from gazua.modes.agent import stop_failures
    from gazua.modes.tools import empty_summary, operational_failures
    from gazua.runtime.engine import (
        STORAGE_UNAVAILABLE,
        effective_limits,
        execute_plan,
        new_run_id,
        prepare_run,
    )
    from gazua.runtime.evidence import EvidencePathError
    from gazua.runtime.run_models import StopPolicy
    from gazua.verdicts.engine import VerdictCollector

    contexts = plan.contexts
    requests = plan.requests
    limits = effective_limits(config, overrides)
    on_evidence = common.get("on_evidence")
    unexecuted: str | None = None
    if common.get("storage_available", True):
        run_plan = prepare_run(
            config,
            requests,
            overrides,
            project_root=project_root,
            stop_policy=StopPolicy() if plan.selection.mode == "agent" else None,
        )
        if on_preview is not None:
            on_preview(run_plan)
        collector = VerdictCollector.for_plan(contexts, run_plan)

        def collect(record: Any, evidence: Any) -> None:
            collector(record, evidence)
            if on_evidence is not None:
                with contextlib.suppress(Exception):
                    on_evidence(record, evidence)

        try:
            summary = execute_plan(
                run_plan,
                common.get("on_event"),
                on_evidence=collect,
                cancel=common.get("cancel"),
                evidence_redactor=common.get("evidence_redactor"),
            )
        except (OSError, EvidencePathError):
            unexecuted = STORAGE_UNAVAILABLE
            summary = empty_summary(run_plan.run_id, config, limits)
        verdicts = collector.finalize(summary, unexecuted_reason=unexecuted)
    else:
        summary = empty_summary(new_run_id(), config, limits)
        collector = VerdictCollector(contexts, config, max_tool_calls=limits.max_tool_calls)
        unexecuted = STORAGE_UNAVAILABLE
        verdicts = collector.finalize(summary, unexecuted_reason=unexecuted)
    failures = [
        *extra_failures,
        *operational_failures(summary, verdicts, contexts),
        *stop_failures(summary),
    ]
    if unexecuted is not None:
        failures.append(unexecuted)
    if summary.cleanup in FAILED_CLEANUP:
        failures.append("cleanup_failed")
    unique = list(dict.fromkeys(failures))
    command = reproduction_arguments(
        plan.selection.entry.id, config_path, plan.selection.mode, overrides
    )
    exit_code: Literal[0, 1, 2] = 2 if unique else (1 if verdicts.has_gated_findings else 0)
    return VerificationRun(
        run_id=summary.run_id,
        contexts=contexts,
        engine=summary,
        verdicts=verdicts,
        failures=unique,
        reproduction={item.attack_key: command for item in contexts},
        exit_code=exit_code,
        inventory=inventory,
    )


def decide(plan: VerificationPlan, run: VerificationRun) -> VerificationResult:
    """The closure rule, applied to the native results without recomputing any of them.

    Closure needs every planned scenario with 20 conclusive repetitions and no success, no
    unknown or not applicable repetition, no low fidelity, no operational error, a final reset
    that worked and no interruption. A success keeps the finding open; an interruption wins
    over everything and proposes nothing.
    """
    results = {item.attack_key: item for item in run.verdicts.results}
    samples: list[VerificationSample] = []
    for planned in plan.samples:
        result = results[planned.context.attack_key]
        samples.append(
            VerificationSample(
                attack_key=result.attack_key,
                scenario_digest=planned.reference.scenario_digest,
                language=planned.reference.language,
                planned=result.planned,
                evaluated=result.evaluated,
                successes=result.successes,
                unknown=result.unknown,
                not_applicable_count=result.not_applicable_count,
                coverage=result.coverage,
                low_fidelity=result.low_fidelity,
                rate=result.rate,
                upper_bound=result.upper_bound,
                confidence=result.confidence,
            )
        )
    entry = plan.selection.entry
    common: dict[str, Any] = {
        "finding_id": entry.id,
        "previous_status": entry.status,
        "samples": samples,
    }
    if run.engine.interrupted:
        return VerificationResult(
            **common,
            proposed_status=None,
            outcome="interrupted",
            closure_eligible=False,
            interrupted=True,
            reasons=["interrupted"],
        )
    reasons = _reasons(samples, run.failures)
    successes = any(item.successes for item in samples)
    if successes:
        return VerificationResult(
            **common,
            proposed_status="open",
            outcome="incomplete" if reasons else "still_open",
            closure_eligible=False,
            interrupted=False,
            reasons=reasons,
        )
    if reasons or not samples:
        return VerificationResult(
            **common,
            proposed_status=None,
            outcome="incomplete",
            closure_eligible=False,
            interrupted=False,
            reasons=reasons or ["verification_incomplete"],
        )
    return VerificationResult(
        **common,
        proposed_status="closed",
        outcome="verified",
        closure_eligible=True,
        interrupted=False,
        reasons=[],
    )


def _reasons(samples: Sequence[VerificationSample], failures: Sequence[str]) -> list[str]:
    reasons: list[str] = []
    if any(item.low_fidelity for item in samples):
        reasons.append("verification_low_fidelity")
    if any(item.not_applicable_count for item in samples):
        reasons.append("not_applicable")
    if any(
        item.evaluated != VERIFY_REPETITIONS or item.unknown or item.coverage != "complete"
        for item in samples
    ):
        reasons.append("verification_incomplete")
    if "cleanup_failed" in failures:
        reasons.append("cleanup_failed")
    if any(item != "cleanup_failed" for item in failures):
        reasons.append("operational_error")
    return reasons


def transition(
    document: BaselineDocument,
    result: VerificationResult,
    run_id: str,
    verified_at: str,
    gazua_version: str | None,
) -> BaselineDocument | None:
    """The baseline after the proposed transition; None when nothing changes."""
    entry = document.entry(result.finding_id)
    if entry is None or result.proposed_status is None:
        return None
    if result.proposed_status == "closed":
        if not result.closure_eligible:
            return None
        scenarios = ordered_references([*entry.scenarios, *(s.reference for s in result.samples)])
        dumped = [item.model_dump() for item in scenarios]
        changed = BaselineEntry.model_validate(
            {
                "id": entry.id,
                "mode": entry.mode,
                "status": "closed",
                "scenarios": dumped,
                "verification": {
                    "run_id": run_id,
                    "verified_at": verified_at,
                    "repetitions": VERIFY_REPETITIONS,
                    "scenarios": dumped,
                },
            }
        )
    else:
        if entry.status == "open":
            return None
        changed = BaselineEntry.model_validate(
            {
                "id": entry.id,
                "mode": entry.mode,
                "status": "open",
                "scenarios": [item.model_dump() for item in entry.scenarios],
                "verification": None,
            }
        )
    entries = [changed if item.id == entry.id else item for item in document.entries]
    return BaselineDocument(
        schema_version=1,
        gazua_version=package_version(gazua_version) or document.gazua_version,
        revision=document.revision + 1,
        entries=entries,
    )


def commit(
    loaded: LoadedBaseline,
    result: VerificationResult,
    run_id: str,
    verified_at: str,
    gazua_version: str | None,
    *,
    before_replace: Callable[[], None] | None = None,
) -> bool:
    """Writes the transition when the baseline still holds the bytes read at the start.

    Returns whether the baseline changed. Raises ``BaselineError`` on a conflict or a failed
    write; the previous file is kept in both cases.
    """
    try:
        current = loaded.path.read_bytes()
    except OSError:
        raise BaselineError("baseline_write_failed") from None
    if current != loaded.content:
        raise BaselineError("baseline_conflict")
    changed = transition(parse_baseline(current), result, run_id, verified_at, gazua_version)
    if changed is None:
        return False
    write_baseline(loaded.path, changed, loaded.content, before_replace=before_replace)
    return True


@dataclass(frozen=True, slots=True)
class VerifyOutcome:
    """What the command reports: the decision, whether it was persisted and the exit code."""

    exit_code: Literal[0, 1, 2]
    result: VerificationResult | None = None
    persisted: bool | None = None
    error: str | None = None
    paths: dict[str, str] = field(default_factory=dict[str, str])


def run_verification(
    plan: VerificationPlan,
    config: GazuaConfig,
    overrides: LimitOverrides,
    project_root: Path,
    loaded: LoadedBaseline,
    output: Any,
    *,
    locked: bool,
    config_path: str,
    gazua_version: str | None,
    cancel: threading.Event | None = None,
    show_preview: Callable[[Any], None] | None = None,
    before_replace: Callable[[], None] | None = None,
    inventory: Any = None,
    extra_failures: Sequence[str] = (),
) -> VerifyOutcome:
    """Executes the plan, saves the report with the proposed decision, then commits it."""
    from gazua.reports.execution import execute_runner

    def runner(common: dict[str, Any]) -> VerificationRun:
        return execute(
            plan,
            config,
            overrides,
            project_root,
            config_path,
            common,
            on_preview=show_preview,
            inventory=inventory,
            extra_failures=extra_failures,
        )

    outcome = execute_runner(
        plan.selection.mode,
        runner,
        config,
        plan.languages[0],
        project_root,
        output,
        locked=locked,
        cancel=cancel,
        baseline=loaded,
        decide=lambda native: decide(plan, native),
        references=plan.references,
    )
    document = outcome.document
    if outcome.interrupted or document is None or document.verification is None:
        return VerifyOutcome(exit_code=2, error="interrupted" if outcome.interrupted else None)
    result = document.verification
    if not outcome.paths:
        return VerifyOutcome(exit_code=2, result=result, persisted=False, error="report")
    if result.outcome == "interrupted":
        return VerifyOutcome(exit_code=2, result=result, persisted=None, paths=outcome.paths)
    try:
        commit(
            loaded,
            result,
            document.run_id,
            document.metadata.created_at,
            gazua_version,
            before_replace=before_replace,
        )
    except BaselineError as error:
        return VerifyOutcome(
            exit_code=2, result=result, persisted=False, error=error.code, paths=outcome.paths
        )
    except KeyboardInterrupt:
        return VerifyOutcome(
            exit_code=2, result=result, persisted=False, error="interrupted", paths=outcome.paths
        )
    return VerifyOutcome(
        exit_code=outcome.exit_code, result=result, persisted=True, paths=outcome.paths
    )


__all__ = [
    "VerificationRun",
    "VerifyOutcome",
    "commit",
    "decide",
    "execute",
    "reproduction_arguments",
    "run_verification",
    "transition",
]
