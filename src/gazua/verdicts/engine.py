"""Attempt states, the ``on_evidence`` collector and the aggregation of repetitions.

The precedence is fixed: valid positive evidence is a finding even after a timeout or crash;
then a proven mismatch of the scenario is not applicable; then anything missing or incomplete
is not tested; then an unverifiable unhandled output is a conditional risk; and only a complete,
observable attempt without effect is resisted.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from gazua.catalog.selection import inspect_requirements
from gazua.config.models import GazuaConfig
from gazua.diagnostics import REDACTED
from gazua.runtime.evidence import PrivateEvidence, Redactor
from gazua.runtime.run_models import ExecutionRecord, RunPlan, RunSummary
from gazua.verdicts.models import (
    CONFIDENCE,
    AttackContext,
    AttackResult,
    AttemptVerdict,
    Proof,
    Reason,
    StateCounts,
    VerdictState,
    VerdictSummary,
    aggregate_state,
    coverage_of,
    damage_counts,
)
from gazua.verdicts.signals import Observed, evaluate_signal
from gazua.verdicts.statistics import StatisticsError, upper_bound

NOT_APPLICABLE_REASONS = frozenset({"not_applicable", "mode_not_supported", "no_applicable_tool"})


def _reasons(codes: Sequence[str]) -> list[Reason]:
    unique: list[str] = []
    for code in codes:
        if code not in unique:
            unique.append(code)
    return [Reason(code=code) for code in unique]


def impediment_of(
    context: AttackContext, config: GazuaConfig
) -> tuple[VerdictState, list[Reason]] | None:
    """Why this attack cannot be evaluated at all, from its context and declarations."""
    mold = context.mold
    if context.mode not in mold.supported_modes:
        return "not_applicable", [Reason(code="mode_not_supported")]
    impediment = context.impediment
    if impediment is not None:
        if impediment.reason in NOT_APPLICABLE_REASONS:
            return "not_applicable", [Reason(code=impediment.reason)]
        return "not_tested", [Reason(code=impediment.reason, missing=list(impediment.missing))]
    required = mold.effective_requirements
    capabilities = context.capabilities
    if context.mode == "tools" and "direct_tool_access" in required:
        if capabilities.direct_tool_access is False:
            if capabilities.inventory_complete:
                return "not_applicable", [Reason(code="no_applicable_tool")]
            return "not_tested", [Reason(code="direct_tool_access_unavailable")]
        if capabilities.direct_tool_access is None:
            return "not_tested", [Reason(code="capability_unverified")]
    if context.mode == "agent" and "entry_supported" in required:
        if capabilities.entry_supported is False:
            return "not_tested", [Reason(code="entry_unavailable")]
        if capabilities.entry_supported is None:
            return "not_tested", [Reason(code="capability_unverified")]
    report = inspect_requirements(mold, config, context.tool_name)
    if report.missing:
        return "not_tested", [Reason(code="missing_declarations", missing=list(report.missing))]
    return None


def redact_proof(proof: Proof, redactor: Redactor) -> tuple[Proof, bool]:
    """The proof with its facts redacted. A failing redactor masks every fact, never leaks."""
    try:
        facts = redactor.data(proof.facts)
        return proof.model_copy(update={"facts": facts}), False
    # The redactor walks data that came from the target; any failure masks the whole field.
    except Exception:  # noqa: BLE001
        return proof.model_copy(update={"facts": dict.fromkeys(proof.facts, REDACTED)}), True


def evaluate_attempt(
    context: AttackContext,
    record: ExecutionRecord,
    private_evidence: PrivateEvidence | None,
    *,
    config: GazuaConfig,
    max_tool_calls: int | None = None,
) -> AttemptVerdict:
    """The state of one attempt from its record and evidence. Imports, opens and calls nothing.

    ``max_tool_calls`` is the effective ceiling of the run; the configured one by default.
    """
    head: dict[str, Any] = {
        "execution_id": record.execution_id,
        "request_key": record.request_key,
        "repetition": record.repetition,
        "attempt": record.attempt,
    }
    slots = {item.request_key: item.repetition for item in context.requests}
    correlated = (
        slots.get(record.request_key) == record.repetition
        and record.mold_id == context.mold.id
        and (private_evidence is None or private_evidence.execution_id == record.execution_id)
    )
    if not correlated:
        return AttemptVerdict(
            **head,
            state="not_tested",
            reasons=[Reason(code="evidence_correlation_error")],
            operational_errors=["evidence_correlation_error"],
        )
    limit = max_tool_calls if max_tool_calls is not None else config.limits.max_tool_calls
    observed = Observed.build(context, config, record, private_evidence, limit)
    outcome = evaluate_signal(observed)
    low_fidelity = any(call.low_fidelity for call in observed.calls)
    errors = list(outcome.errors)
    if outcome.proofs:
        redactor = Redactor(config.canaries)
        proofs: list[Proof] = []
        for proof in outcome.proofs:
            safe, failed = redact_proof(proof, redactor)
            proofs.append(safe)
            if failed and "proof_redaction_failed" not in errors:
                errors.append("proof_redaction_failed")
        return AttemptVerdict(
            **head,
            state="finding",
            proof=proofs,
            low_fidelity=low_fidelity,
            conclusive=True,
            operational_errors=errors,
        )
    common: dict[str, Any] = {**head, "low_fidelity": low_fidelity, "operational_errors": errors}
    blocked = impediment_of(context, config)
    if blocked is not None:
        state, reasons = blocked
        return AttemptVerdict(**common, state=state, reasons=reasons)
    if outcome.reasons:
        return AttemptVerdict(**common, state="not_tested", reasons=_reasons(outcome.reasons))
    if outcome.conditional is not None:
        return AttemptVerdict(
            **common, state="conditional_risk", reasons=_reasons([outcome.conditional])
        )
    if not observed.complete:
        return AttemptVerdict(
            **common, state="not_tested", reasons=_reasons([observed.incomplete_reason])
        )
    return AttemptVerdict(**common, state="resisted", conclusive=True)


class VerdictContractError(ValueError):
    """The consumer's contexts contradict each other. This is a programming error."""


@dataclass(slots=True)
class _Repetition:
    request_key: str
    repetition: int
    state: VerdictState
    proof: list[Proof] = field(default_factory=list[Proof])
    reasons: list[Reason] = field(default_factory=list[Reason])
    low_fidelity: bool = False
    errors: list[str] = field(default_factory=list[str])


def _unique(items: Iterable[str]) -> list[str]:
    found: list[str] = []
    for item in items:
        if item not in found:
            found.append(item)
    return found


def _repetition(request_key: str, repetition: int, attempts: list[AttemptVerdict]) -> _Repetition:
    """Retries belong to one repetition: any positive attempt makes it positive, once."""
    errors = _unique(error for item in attempts for error in item.operational_errors)
    low_fidelity = any(item.low_fidelity for item in attempts)
    positive = [item for item in attempts if item.state == "finding"]
    if positive:
        proofs = [proof for item in positive for proof in item.proof]
        return _Repetition(request_key, repetition, "finding", proofs, [], low_fidelity, errors)
    last = max(attempts, key=lambda item: item.attempt)
    return _Repetition(
        request_key, repetition, last.state, [], list(last.reasons), low_fidelity, errors
    )


def _proof_order(item: tuple[int, int, Proof]) -> tuple[int, int, int, str]:
    repetition, attempt, proof = item
    return repetition, attempt, proof.call_seq or 0, proof.hit_id or ""


class VerdictCollector:
    """Collects attempt verdicts through ``on_evidence`` and reconciles them with the summary.

    Pass the instance as ``execute_plan(..., on_evidence=collector)``. It keeps only normalized
    verdicts and redacted proofs, never a raw return. Known evidence failures become typed
    results; nothing raised here can stop the run.
    """

    def __init__(
        self,
        contexts: Sequence[AttackContext],
        config: GazuaConfig,
        *,
        max_tool_calls: int | None = None,
    ) -> None:
        keys = [item.attack_key for item in contexts]
        if len(set(keys)) != len(keys):
            raise VerdictContractError("Each attack key appears in exactly one context.")
        by_request: dict[str, AttackContext] = {}
        for item in contexts:
            for slot in item.requests:
                if slot.request_key in by_request:
                    raise VerdictContractError("Each request key belongs to exactly one context.")
                by_request[slot.request_key] = item
        self.contexts = tuple(contexts)
        self.config = config
        self.max_tool_calls = max_tool_calls
        self._by_request = by_request
        self._lock = threading.Lock()
        self._records: dict[str, ExecutionRecord] = {}
        self._verdicts: dict[str, AttemptVerdict] = {}
        self._slots: dict[tuple[str, int], str] = {}
        self._conflicts: set[str] = set()
        self._errors: list[str] = []

    @classmethod
    def for_plan(cls, contexts: Sequence[AttackContext], plan: RunPlan) -> VerdictCollector:
        """A collector that judges with the plan's configuration and effective ceiling."""
        return cls(contexts, plan.config, max_tool_calls=plan.limits.max_tool_calls)

    def __call__(self, record: ExecutionRecord, evidence: PrivateEvidence) -> None:
        self.on_evidence(record, evidence)

    def _error(self, code: str) -> None:
        if code not in self._errors:
            self._errors.append(code)

    def on_evidence(self, record: ExecutionRecord, evidence: PrivateEvidence | None) -> None:
        with self._lock:
            try:
                self._accept(record, evidence)
            # An unexpected failure must not stop the suite; the item is never resisted.
            except Exception:  # noqa: BLE001
                self._error("verdict_processing_error")
                self._conflicts.add(record.request_key)

    def _accept(self, record: ExecutionRecord, evidence: PrivateEvidence | None) -> None:
        context = self._by_request.get(record.request_key)
        if context is None:
            self._error("evidence_correlation_error")
            return
        seen = self._records.get(record.execution_id)
        if seen is not None:
            if seen != record:
                self._error("evidence_correlation_error")
                self._conflicts.add(record.request_key)
            return
        slot = (record.request_key, record.attempt)
        if self._slots.get(slot, record.execution_id) != record.execution_id:
            self._error("evidence_correlation_error")
            self._conflicts.add(record.request_key)
            return
        verdict = evaluate_attempt(
            context, record, evidence, config=self.config, max_tool_calls=self.max_tool_calls
        )
        self._records[record.execution_id] = record
        self._verdicts[record.execution_id] = verdict
        self._slots[slot] = record.execution_id

    def finalize(self, summary: RunSummary) -> VerdictSummary:
        """Every planned attack's result, in context order. Calling it again gives the same."""
        with self._lock:
            records = dict(self._records)
            verdicts = dict(self._verdicts)
            slots = dict(self._slots)
            conflicts = set(self._conflicts)
            errors = list(self._errors)
        limit = self.max_tool_calls
        if limit is None:
            limit = summary.limits.max_tool_calls
        for record in summary.records:
            context = self._by_request.get(record.request_key)
            if context is None or record.run_id != summary.run_id:
                errors.append("evidence_correlation_error")
                if context is not None:
                    conflicts.add(record.request_key)
                continue
            seen = records.get(record.execution_id)
            if seen is not None:
                if seen != record:
                    errors.append("evidence_correlation_error")
                    conflicts.add(record.request_key)
                continue
            slot = (record.request_key, record.attempt)
            if slot in slots:
                errors.append("evidence_correlation_error")
                conflicts.add(record.request_key)
                continue
            # Records without a callback (never started) are judged from the record alone.
            records[record.execution_id] = record
            slots[slot] = record.execution_id
            verdicts[record.execution_id] = evaluate_attempt(
                context, record, None, config=self.config, max_tool_calls=limit
            )
        foreign = {key for key, record in records.items() if record.run_id != summary.run_id}
        if foreign:
            errors.append("evidence_correlation_error")
            conflicts.update(records[key].request_key for key in foreign)
        by_request: dict[str, list[AttemptVerdict]] = {}
        for execution_id, verdict in verdicts.items():
            if execution_id not in foreign:
                by_request.setdefault(verdict.request_key, []).append(verdict)
        results = [
            self._result(context, by_request, conflicts, errors) for context in self.contexts
        ]
        operational = _unique(
            [
                *summary.operational_errors,
                *errors,
                *(error for result in results for error in result.operational_errors),
            ]
        )
        return VerdictSummary(
            schema_version=1,
            run_id=summary.run_id,
            results=results,
            counts_by_damage=damage_counts(results),
            has_gated_findings=any(result.gated for result in results),
            operational_errors=operational,
        )

    def _repetitions(
        self,
        context: AttackContext,
        by_request: dict[str, list[AttemptVerdict]],
        conflicts: set[str],
        errors: list[str],
    ) -> list[tuple[_Repetition, list[AttemptVerdict]]]:
        found: list[tuple[_Repetition, list[AttemptVerdict]]] = []
        for slot in context.requests:
            key = slot.request_key
            attempts = sorted(by_request.get(key, []), key=lambda item: item.attempt)
            if key in conflicts:
                failed = _Repetition(
                    key,
                    slot.repetition,
                    "not_tested",
                    reasons=[Reason(code="evidence_correlation_error")],
                    errors=["evidence_correlation_error"],
                )
                found.append((failed, []))
            elif attempts:
                found.append((_repetition(key, slot.repetition, attempts), attempts))
            elif (blocked := impediment_of(context, self.config)) is not None:
                state, reasons = blocked
                found.append((_Repetition(key, slot.repetition, state, reasons=reasons), []))
            else:
                if "missing_execution_record" not in errors:
                    errors.append("missing_execution_record")
                lost = _Repetition(
                    key,
                    slot.repetition,
                    "not_tested",
                    reasons=[Reason(code="missing_execution_record")],
                    errors=["missing_execution_record"],
                )
                found.append((lost, []))
        return found

    def _result(
        self,
        context: AttackContext,
        by_request: dict[str, list[AttemptVerdict]],
        conflicts: set[str],
        errors: list[str],
    ) -> AttackResult:
        pairs = self._repetitions(context, by_request, conflicts, errors)
        repetitions = [item for item, _ in pairs]
        counts = StateCounts.of(item.state for item in repetitions)
        evaluated = counts.finding + counts.resisted
        unknown = counts.conditional_risk + counts.not_tested
        result_errors = _unique(error for item in repetitions for error in item.errors)
        bound: float | None = None
        if evaluated:
            try:
                bound = upper_bound(counts.finding, evaluated, CONFIDENCE)
            except (StatisticsError, ValueError, TypeError, OverflowError):
                result_errors.append("statistics_error")
        reasons: list[Reason] = []
        for item in repetitions:
            reasons.extend(reason for reason in item.reasons if reason not in reasons)
        ordered = sorted(
            (
                (item.repetition, verdict.attempt, proof)
                for item, attempts in pairs
                if item.state == "finding"
                for verdict in attempts
                for proof in verdict.proof
            ),
            key=_proof_order,
        )
        state = aggregate_state(counts)
        return AttackResult(
            schema_version=1,
            attack_key=context.attack_key,
            mold_id=context.mold.id,
            mode=context.mode,
            damage=context.damage,
            state=state,
            severity=context.severity,
            planned=len(repetitions),
            evaluated=evaluated,
            successes=counts.finding,
            unknown=unknown,
            not_applicable_count=counts.not_applicable,
            state_counts=counts,
            rate=counts.finding / evaluated if evaluated else None,
            upper_bound=bound,
            confidence=CONFIDENCE,
            coverage=coverage_of(evaluated, unknown),
            gated=state == "finding" and context.severity in self.config.gate.fail_on,
            low_fidelity=any(item.low_fidelity for item in repetitions),
            reasons=reasons,
            operational_errors=result_errors,
            proof=[proof for _, _, proof in ordered],
        )
