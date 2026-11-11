"""Contracts of the verdict engine: attack contexts, proofs, attempt verdicts and attack results.

A result is decided only from recorded effects. No field accepts a success flag from the
target: counts, rates and gates are checked against each other, so an inconsistent result is
rejected instead of being shown.
"""

from __future__ import annotations

import json
import math
from collections.abc import Iterable
from typing import Annotated, Any, Literal, TypeAlias, get_args

from pydantic import BaseModel, ConfigDict, Field, JsonValue, TypeAdapter, model_validator

from gazua.catalog.bindings import BindingImpediment
from gazua.catalog.models import Damage, Mode, Mold, Requirement, Signal
from gazua.config.models import SCHEMA_DIALECT, Severity
from gazua.runtime.observations import (
    MemoryObservation,
    ObservationEnvelope,
    ReturnObservation,
    SinkObservation,
)
from gazua.runtime.run_models import GazuaId, LocalReference, NonEmptyText

ATTACK_RESULT_SCHEMA_FILE = "attack-result-v1.schema.json"
EFFECT_OBSERVATION_SCHEMA_FILE = "effect-observation-v1.schema.json"
_SCHEMA_BASE = "https://raw.githubusercontent.com/JoaoVictorVM/gazua/main/src/gazua/schemas/"
CONFIDENCE = 0.95
_RATE_TOLERANCE = 1e-9

VerdictState: TypeAlias = Literal[
    "finding", "conditional_risk", "resisted", "not_tested", "not_applicable"
]
VERDICT_STATES: tuple[VerdictState, ...] = get_args(VerdictState)
Coverage: TypeAlias = Literal["complete", "partial", "none"]
ProofCondition: TypeAlias = Literal[
    "dry_run",
    "attempted_action_only",
    "low_fidelity",
    "raised_after_call",
    "monetary_effect_not_proven",
    "fixture_specific",
    "exfiltration_attempt_only",
    "gazua_ceiling",
    "target_limit_unknown",
    "cost_not_proven",
    "execution_incomplete",
    "truncated_tail",
    "delivered_after_injection",
    "test_sink_only",
    "synthetic_marker",
]
ProofPosition: TypeAlias = Literal["response", "tool_return", "tool_arguments"]
ImpedimentReason: TypeAlias = Literal[
    "missing_declarations",
    "not_applicable",
    "mode_not_supported",
    "no_applicable_tool",
    "entry_unavailable",
    "receiver_unavailable",
    "missing_tool_arguments",
    "tool_signature_unavailable",
    "tool_not_found",
    "tool_name_conflict",
    "tool_unclassified",
]
Code = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$")]
AttackKey = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")]
PathItem = Annotated[str, Field(min_length=1)] | Annotated[int, Field(ge=0)]
Count = Annotated[int, Field(ge=0)]
Probability = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]

EffectObservation = Annotated[
    ReturnObservation | SinkObservation | MemoryObservation, Field(discriminator="kind")
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class RequestSlot(_Strict):
    """One logical repetition of an attack. Its retries are attempts of the same slot."""

    request_key: NonEmptyText
    repetition: Annotated[int, Field(ge=1)]


class Capabilities(_Strict):
    """What the consumer knows about this attack's channels.

    ``None`` means unknown, which never proves that something is absent. ``inventory_complete``
    says the tool inventory was read in full, the only way a missing tool means not applicable.
    """

    direct_tool_access: bool | None = None
    entry_supported: bool | None = None
    inventory_complete: bool = False
    tool_visibility: bool = True
    receiver_transport: bool = False
    observation_envelope: bool = False


class ResultPaths(_Strict):
    """Where the record id and owner are in a tool's return, as names and list indexes only."""

    id: Annotated[list[PathItem], Field(min_length=1, max_length=16)]
    owner: Annotated[list[PathItem], Field(min_length=1, max_length=16)]


class Impediment(_Strict):
    """Why an attack could not be prepared. It is never read as resistance."""

    reason: ImpedimentReason
    missing: list[Requirement] = Field(default_factory=list[Requirement])

    @classmethod
    def from_binding(cls, impediment: BindingImpediment) -> Impediment:
        return cls(reason=impediment.reason, missing=list(impediment.missing))


class AttackContext(_Strict):
    """One attack unit: mold, mode, tool, fixture record, canary and variant.

    Its key is assigned by the consumer and stays stable across runs. A different tool or
    record is a different unit, so rates of different scenarios are never combined.
    """

    attack_key: AttackKey
    mold: Mold
    mode: Mode
    tool_name: NonEmptyText | None = None
    record_index: Count | None = None
    canary_index: Count | None = None
    marker_id: Literal["markup_marker", "control_marker"] | None = None
    requests: Annotated[list[RequestSlot], Field(min_length=1)]
    capabilities: Capabilities = Field(default_factory=Capabilities)
    result_paths: ResultPaths | None = None
    impediment: Impediment | None = None

    @model_validator(mode="after")
    def _unique_requests(self) -> AttackContext:
        keys = [item.request_key for item in self.requests]
        repetitions = [item.repetition for item in self.requests]
        if len(set(keys)) != len(keys) or len(set(repetitions)) != len(repetitions):
            raise ValueError("Each request key and repetition appears once per attack.")
        return self

    @property
    def signal(self) -> Signal:
        return self.mold.success.signal

    @property
    def damage(self) -> Damage:
        return self.mold.damage

    @property
    def severity(self) -> Severity:
        return self.mold.effective_severity


class Proof(_Strict):
    """Where an effect was observed. It points to redacted evidence and never holds raw values."""

    signal: Signal
    execution_id: GazuaId
    call_seq: Annotated[int, Field(ge=1)] | None = None
    hit_id: NonEmptyText | None = None
    reference: LocalReference | None = None
    canary_index: Count | None = None
    position: ProofPosition | None = None
    conditions: list[ProofCondition] = Field(default_factory=list[ProofCondition])
    facts: dict[str, JsonValue] = Field(default_factory=dict[str, JsonValue])

    @model_validator(mode="after")
    def _located(self) -> Proof:
        located = (self.call_seq, self.hit_id, self.reference) != (None, None, None)
        if not located and not self.facts:
            raise ValueError("A proof needs an evidence locator or an operational fact.")
        if self.reference is not None:
            parts = self.reference.split("/")
            prefix = ["executions", self.execution_id]
            if parts[:2] != prefix or len(parts) < 3 or ".." in parts or "." in parts:
                raise ValueError("A proof reference stays inside its execution folder.")
        return self


class Reason(_Strict):
    """Why a repetition was not tested or stayed conditional, as a closed code."""

    code: Code
    missing: list[Requirement] = Field(default_factory=list[Requirement])


class AttemptVerdict(_Strict):
    """The state of one attempt. ``attempt`` 0 marks a repetition that never got a record."""

    execution_id: GazuaId | None
    request_key: NonEmptyText
    repetition: Annotated[int, Field(ge=1)]
    attempt: Count
    state: VerdictState
    proof: list[Proof] = Field(default_factory=list[Proof])
    reasons: list[Reason] = Field(default_factory=list[Reason])
    low_fidelity: bool = False
    conclusive: bool = False
    operational_errors: list[Code] = Field(default_factory=list[str])

    @model_validator(mode="after")
    def _state_rules(self) -> AttemptVerdict:
        if self.state == "finding" and (not self.proof or self.execution_id is None):
            raise ValueError("A finding needs proof from an execution.")
        if self.state != "finding" and self.proof:
            raise ValueError("Only a finding carries proof.")
        if self.state in ("not_tested", "conditional_risk", "not_applicable") and not self.reasons:
            raise ValueError("This state needs a reason.")
        if self.state == "resisted" and (not self.conclusive or self.execution_id is None):
            raise ValueError("Resisted needs a conclusive evaluation of an execution.")
        return self


class StateCounts(_Strict):
    finding: Count = 0
    conditional_risk: Count = 0
    resisted: Count = 0
    not_tested: Count = 0
    not_applicable: Count = 0

    @property
    def total(self) -> int:
        return sum(getattr(self, state) for state in VERDICT_STATES)

    @classmethod
    def of(cls, states: Iterable[VerdictState]) -> StateCounts:
        counts = dict.fromkeys(VERDICT_STATES, 0)
        for state in states:
            counts[state] += 1
        return cls(**counts)


def aggregate_state(counts: StateCounts) -> VerdictState:
    """The attack state from its repetitions: any finding wins, then any unknown."""
    if counts.finding:
        return "finding"
    if counts.not_tested:
        return "not_tested"
    if counts.conditional_risk:
        return "conditional_risk"
    if counts.resisted:
        return "resisted"
    return "not_applicable"


def coverage_of(evaluated: int, unknown: int) -> Coverage:
    if evaluated == 0:
        return "none"
    return "partial" if unknown else "complete"


class AttackResult(_Strict):
    """The verdict of one attack unit over all its repetitions."""

    model_config = ConfigDict(title="Gazua attack result")

    schema_version: Literal[1]
    attack_key: AttackKey
    mold_id: NonEmptyText
    mode: Mode
    damage: Damage
    state: VerdictState
    severity: Severity
    planned: Annotated[int, Field(ge=1)]
    evaluated: Count
    successes: Count
    unknown: Count
    not_applicable_count: Count
    state_counts: StateCounts
    rate: Probability | None
    upper_bound: Probability | None
    confidence: Annotated[float, Field(ge=CONFIDENCE, le=CONFIDENCE)]
    coverage: Coverage
    gated: bool
    low_fidelity: bool
    reasons: list[Reason]
    operational_errors: list[Code]
    proof: list[Proof]

    @model_validator(mode="after")
    def _consistent(self) -> AttackResult:
        counts = self.state_counts
        problems = [
            counts.total != self.planned,
            self.evaluated != counts.finding + counts.resisted,
            self.successes != counts.finding,
            self.unknown != counts.conditional_risk + counts.not_tested,
            self.not_applicable_count != counts.not_applicable,
            self.state != aggregate_state(counts),
            self.coverage != coverage_of(self.evaluated, self.unknown),
            self.gated and self.state != "finding",
            (self.state == "finding") != bool(self.proof),
            self.state in ("not_tested", "conditional_risk") and not self.reasons,
        ]
        if any(problems):
            raise ValueError("The result's counts, state, coverage and gate disagree.")
        if self.evaluated == 0:
            if self.rate is not None or self.upper_bound is not None:
                raise ValueError("Without evaluated repetitions there is no rate or bound.")
            return self
        if self.rate is None or not math.isclose(
            self.rate, self.successes / self.evaluated, abs_tol=_RATE_TOLERANCE
        ):
            raise ValueError("The rate is successes over evaluated repetitions.")
        if self.upper_bound is None:
            if "statistics_error" not in self.operational_errors:
                raise ValueError("A missing upper bound needs a statistics error.")
        elif self.upper_bound < self.rate - _RATE_TOLERANCE:
            raise ValueError("The upper bound is never below the observed rate.")
        return self


class VerdictSummary(_Strict):
    """Every attack result of one run, with counts per damage and the overall gate."""

    model_config = ConfigDict(title="Gazua verdict summary")

    schema_version: Literal[1]
    run_id: GazuaId
    results: list[AttackResult]
    counts_by_damage: dict[Damage, StateCounts]
    has_gated_findings: bool
    operational_errors: list[Code]

    @model_validator(mode="after")
    def _consistent(self) -> VerdictSummary:
        keys = [result.attack_key for result in self.results]
        if len(set(keys)) != len(keys):
            raise ValueError("Each attack has exactly one result.")
        if self.has_gated_findings != any(result.gated for result in self.results):
            raise ValueError("The gate is the OR of the results' gates.")
        if self.counts_by_damage != damage_counts(self.results):
            raise ValueError("Counts by damage come from the results.")
        return self


def damage_counts(results: Iterable[AttackResult]) -> dict[Damage, StateCounts]:
    grouped: dict[Damage, list[VerdictState]] = {}
    for result in results:
        grouped.setdefault(result.damage, []).append(result.state)
    return {damage: StateCounts.of(states) for damage, states in grouped.items()}


def _schema(document: dict[str, Any], name: str) -> dict[str, Any]:
    return {"$schema": SCHEMA_DIALECT, "$id": _SCHEMA_BASE + name, **document}


def build_attack_result_json_schema() -> dict[str, Any]:
    return _schema(AttackResult.model_json_schema(mode="validation"), ATTACK_RESULT_SCHEMA_FILE)


def build_effect_observation_json_schema() -> dict[str, Any]:
    document = TypeAdapter(EffectObservation).json_schema(mode="validation")
    return _schema(
        {"title": "Gazua effect observation", **document}, EFFECT_OBSERVATION_SCHEMA_FILE
    )


def render_attack_result_json_schema() -> str:
    return json.dumps(build_attack_result_json_schema(), indent=2) + "\n"


def render_effect_observation_json_schema() -> str:
    return json.dumps(build_effect_observation_json_schema(), indent=2) + "\n"


__all__ = [
    "ATTACK_RESULT_SCHEMA_FILE",
    "CONFIDENCE",
    "EFFECT_OBSERVATION_SCHEMA_FILE",
    "VERDICT_STATES",
    "AttackContext",
    "AttackResult",
    "AttemptVerdict",
    "Capabilities",
    "Coverage",
    "EffectObservation",
    "Impediment",
    "MemoryObservation",
    "ObservationEnvelope",
    "Proof",
    "ProofCondition",
    "Reason",
    "RequestSlot",
    "ResultPaths",
    "ReturnObservation",
    "SinkObservation",
    "StateCounts",
    "VerdictState",
    "VerdictSummary",
    "aggregate_state",
    "build_attack_result_json_schema",
    "build_effect_observation_json_schema",
    "coverage_of",
    "damage_counts",
    "render_attack_result_json_schema",
    "render_effect_observation_json_schema",
]
