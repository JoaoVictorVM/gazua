import json
from typing import Any

import jsonschema
import pytest
from pydantic import ValidationError

from gazua.runtime.observations import (
    MemoryObservation,
    ObservationEnvelope,
    ReturnObservation,
    SinkObservation,
)
from gazua.verdicts.models import (
    AttackResult,
    AttemptVerdict,
    Proof,
    VerdictSummary,
    build_attack_result_json_schema,
    build_effect_observation_json_schema,
)


def result_document(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": 1,
        "attack_key": "permission-05:agent",
        "mold_id": "permission-05",
        "mode": "agent",
        "damage": "prompt_only_permission",
        "state": "finding",
        "severity": "critical",
        "planned": 5,
        "evaluated": 5,
        "successes": 1,
        "unknown": 0,
        "not_applicable_count": 0,
        "state_counts": {
            "finding": 1,
            "conditional_risk": 0,
            "resisted": 4,
            "not_tested": 0,
            "not_applicable": 0,
        },
        "rate": 0.2,
        "upper_bound": 0.657408318,
        "confidence": 0.95,
        "coverage": "complete",
        "gated": True,
        "low_fidelity": True,
        "reasons": [],
        "operational_errors": [],
        "proof": [
            {
                "signal": "forbidden_tool_call",
                "execution_id": "GAZUA-exec-0001",
                "call_seq": 1,
                "reference": "executions/GAZUA-exec-0001/calls.redacted.jsonl",
                "conditions": ["dry_run", "attempted_action_only"],
            }
        ],
    }
    document.update(overrides)
    return document


RESISTED_COUNTS = {
    "finding": 0,
    "conditional_risk": 0,
    "resisted": 5,
    "not_tested": 0,
    "not_applicable": 0,
}


@pytest.mark.parametrize(
    "overrides",
    [
        {"planned": 6},
        {"evaluated": 4},
        {"successes": 2},
        {"unknown": 1},
        {"state": "resisted"},
        {"coverage": "partial"},
        {"rate": 0.4},
        {"upper_bound": 0.1},
        {"upper_bound": None},
        {"confidence": 0.975},
        {"proof": []},
        {"rate": None, "upper_bound": None},
        {
            "state": "resisted",
            "successes": 0,
            "state_counts": RESISTED_COUNTS,
            "gated": True,
            "rate": 0.0,
            "upper_bound": 0.45,
            "proof": [],
        },
        {
            "state": "resisted",
            "successes": 0,
            "state_counts": RESISTED_COUNTS,
            "gated": False,
            "rate": 0.0,
            "upper_bound": 0.45,
        },
        {"gated": "yes"},
        {"extra": True},
    ],
)
def test_strict_contracts_reject_inconsistent_counts_and_gates(overrides: dict[str, Any]) -> None:
    valid = AttackResult.model_validate(result_document())
    schema = build_attack_result_json_schema()
    jsonschema.validate(valid.model_dump(mode="json"), schema)

    with pytest.raises(ValidationError):
        AttackResult.model_validate(result_document(**overrides))


def test_states_and_reasons_are_required_where_they_carry_meaning() -> None:
    base = {
        "execution_id": "GAZUA-exec-0001",
        "request_key": "k#r1",
        "repetition": 1,
        "attempt": 1,
    }
    proof = Proof(signal="receiver_hit", execution_id="GAZUA-exec-0001", hit_id="h1")

    AttemptVerdict.model_validate({**base, "state": "finding", "proof": [proof]})
    for document in (
        {**base, "state": "finding"},
        {**base, "state": "not_tested"},
        {**base, "state": "conditional_risk"},
        {**base, "state": "resisted"},
        {**base, "state": "resisted", "conclusive": True, "proof": [proof]},
        {**base, "state": "approved", "conclusive": True},
    ):
        with pytest.raises(ValidationError):
            AttemptVerdict.model_validate(document)

    with pytest.raises(ValidationError):
        Proof(signal="receiver_hit", execution_id="GAZUA-exec-0001")
    with pytest.raises(ValidationError):
        Proof(
            signal="receiver_hit",
            execution_id="GAZUA-exec-0001",
            reference="executions/GAZUA-exec-0002/hits.redacted.jsonl",
        )
    with pytest.raises(ValidationError):
        Proof(
            signal="receiver_hit",
            execution_id="GAZUA-exec-0001",
            reference="executions/GAZUA-exec-0001/../../private/x",
        )


def test_summary_gate_and_damage_counts_are_derived() -> None:
    result = AttackResult.model_validate(result_document())
    summary = {
        "schema_version": 1,
        "run_id": "GAZUA-run-1",
        "results": [result.model_dump()],
        "counts_by_damage": {
            "prompt_only_permission": {
                "finding": 1,
                "conditional_risk": 0,
                "resisted": 0,
                "not_tested": 0,
                "not_applicable": 0,
            }
        },
        "has_gated_findings": True,
        "operational_errors": [],
    }

    VerdictSummary.model_validate(summary)
    with pytest.raises(ValidationError):
        VerdictSummary.model_validate({**summary, "has_gated_findings": False})
    with pytest.raises(ValidationError):
        VerdictSummary.model_validate({**summary, "counts_by_damage": {}})
    with pytest.raises(ValidationError):
        VerdictSummary.model_validate({**summary, "results": [result.model_dump()] * 2})


def test_observations_accept_only_concrete_structured_effects() -> None:
    schema = build_effect_observation_json_schema()
    head = {"schema_version": 1, "execution_id": "GAZUA-exec-0001"}
    sink = {**head, "kind": "sink", "effect": True, "proof": {"marker_id": "m", "observed": "raw"}}
    returned = {**head, "kind": "tool_return", "call_seq": 1, "original": None, "delivered": None}
    memory = {
        **head,
        "kind": "memory",
        "marker_id": "m",
        "session_id": "s",
        "write_turn": 1,
        "read_turn": 2,
        "written_value": "w",
        "read_value": "w",
        "reset_before": "succeeded",
        "reset_between": False,
    }
    for model, document in (
        (SinkObservation, sink),
        (ReturnObservation, returned),
        (MemoryObservation, memory),
    ):
        model.model_validate(document)
        jsonschema.validate(json.loads(json.dumps(document)), schema)

    for model, document in (
        (SinkObservation, {**sink, "effect": "true"}),
        (SinkObservation, {**sink, "proof": {}}),
        (SinkObservation, {**sink, "proof": {"marker_id": "m"}}),
        (SinkObservation, {**sink, "proof": {"observed": "raw"}}),
        (SinkObservation, {**sink, "error": "sink_error"}),
        (SinkObservation, {**head, "kind": "sink", "effect": None, "proof": None}),
        (ReturnObservation, {**head, "kind": "tool_return", "call_seq": 1, "original": 1}),
        (ReturnObservation, {**returned, "unavailable_reason": "too_large"}),
        (MemoryObservation, {**memory, "read_turn": 1}),
        (ObservationEnvelope, {"gazua_observation_version": 1, "observations": []}),
        (
            ObservationEnvelope,
            {"gazua_observation_version": 1, "response": "x", "observations": [returned]},
        ),
    ):
        with pytest.raises(ValidationError):
            model.model_validate(document)
