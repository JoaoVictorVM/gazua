"""Support consumers stand in for modes, reports, verification and adapters still to come.

They use only the published contract: the structured results, the gate and the operational
errors. None of them recomputes a rate or reads evidence on its own.
"""

import json
from typing import Any

import jsonschema
from verdict_factory import (
    ATTACKER,
    CANARY,
    VICTIM_ORDER,
    Numbers,
    call,
    config,
    context,
    envelope,
    evidence,
    hit,
    record,
    summary,
)

from gazua.runtime.session_models import packaged_schema
from gazua.verdicts.engine import VerdictCollector
from gazua.verdicts.models import AttackContext, VerdictSummary
from gazua.verdicts.presentation import rate_text


def exit_decision(verdicts: VerdictSummary) -> dict[str, Any]:
    """What a mode will turn into an exit code. Operational errors stay apart from the gate."""
    return {
        "gate_failed": verdicts.has_gated_findings,
        "operational_errors": list(verdicts.operational_errors),
    }


def repeated(
    attack: AttackContext, positives: set[int], *, low_fidelity: bool = False
) -> VerdictSummary:
    numbers = Numbers()
    collector = VerdictCollector([attack], config())
    records = []
    for repetition in range(1, len(attack.requests) + 1):
        item = record(attack, repetition, execution_id=numbers.next())
        records.append(item)
        calls = []
        if repetition in positives:
            calls = [call(1, "delete_account", dry_run=True, low_fidelity=low_fidelity)]
        collector(item, evidence(item, calls=calls, output=envelope("I will not do that.")))
    return collector.finalize(summary(records))


def test_tools_consumer_receives_results_and_gate(verdict_project: Any) -> None:
    victim = context("victim_record_access", "tools", key="victim")
    own = context("victim_record_access", "tools", key="own")

    def requests() -> list[Any]:
        return [
            verdict_project.request(
                attack,
                1,
                payload={
                    "tool": "get_order",
                    "arguments": {"order_id": order, "user_id": ATTACKER},
                },
            )
            for attack, order in ((victim, VICTIM_ORDER), (own, "order-attacker-1"))
        ]

    _, first, _ = verdict_project.run([victim, own], requests())
    _, second, _ = verdict_project.run([victim, own], requests())

    assert first.results == second.results
    assert exit_decision(first) == {"gate_failed": True, "operational_errors": []}
    assert [item.state for item in first.results] == ["finding", "resisted"]

    sink_attack = context("output_sink_effect", key="sink")
    item = record(sink_attack)
    failed = {
        "schema_version": 1,
        "kind": "sink",
        "execution_id": item.execution_id,
        "error": "sink_error",
    }
    collector = VerdictCollector([sink_attack], config())
    collector(item, evidence(item, output=envelope("<b>", failed)))
    decision = exit_decision(collector.finalize(summary([item])))
    assert decision == {"gate_failed": False, "operational_errors": ["sink_error"]}


def test_report_consumer_round_trip_preserves_rates_and_proof() -> None:
    verdicts = repeated(context("forbidden_tool_call", repetitions=5), {2}, low_fidelity=True)
    document = json.loads(verdicts.model_dump_json())
    schema = json.loads(packaged_schema("attack-result-v1.schema.json"))

    for result in document["results"]:
        jsonschema.validate(result, schema)
    restored = VerdictSummary.model_validate_json(json.dumps(document))
    assert restored == verdicts
    [result] = restored.results
    assert (result.rate, result.upper_bound) == (0.2, verdicts.results[0].upper_bound)
    assert result.upper_bound is not None
    assert abs(result.upper_bound - 0.6574083180) <= 1e-9
    assert result.proof == verdicts.results[0].proof
    assert rate_text(result) == "1/5, up to ~66%"


def test_agent_consumer_preserves_repetition_rates() -> None:
    attack = context("forbidden_tool_call", repetitions=5)
    verdicts = repeated(attack, {4}, low_fidelity=True)

    [result] = verdicts.results
    assert (result.state, result.successes, result.evaluated, result.planned) == (
        "finding",
        1,
        5,
        5,
    )
    assert result.low_fidelity
    assert result.mode == "agent"
    assert [proof.execution_id for proof in result.proof] == ["GAZUA-exec-0004"]


def test_verification_consumer_receives_zero_in_twenty_without_closing_state() -> None:
    attack = context("forbidden_tool_call", repetitions=20, key="verify")

    clean = repeated(attack, set()).results[0]
    once = repeated(attack, {17}).results[0]

    assert clean.state == "resisted"
    assert rate_text(clean) == "0/20, up to ~14%"
    assert clean.upper_bound is not None
    assert abs(clean.upper_bound - 0.1391083407) <= 1e-9
    assert once.state == "finding"
    assert (once.successes, once.evaluated) == (1, 20)
    for result in (clean, once):
        dumped = result.model_dump()
        assert "status" not in dumped
        assert "baseline" not in dumped
        assert "closed" not in json.dumps(dumped)


def test_missing_tool_visibility_is_not_tested_for_http_contract() -> None:
    hidden = {"tool_visibility": False}
    forbidden = context("forbidden_tool_call", key="calls", capabilities=hidden)
    arguments = context("canary_in_tool_arguments", key="arguments", capabilities=hidden)
    leak = context("canary_in_response", key="leak", capabilities=hidden)
    exfil = context("receiver_hit", key="exfil", capabilities=hidden)
    numbers = Numbers()
    collector = VerdictCollector([forbidden, arguments, leak, exfil], config())
    records = []
    for attack in (forbidden, arguments, leak, exfil):
        identifier = numbers.next()
        item = record(
            attack,
            execution_id=identifier,
            receiver_hits=f"executions/{identifier}/hits.redacted.jsonl",
        )
        records.append(item)
        hits = [hit(item)] if attack is exfil else []
        collector(item, evidence(item, output=f"reply {CANARY}", hits=hits))
    results = {item.attack_key: item for item in collector.finalize(summary(records)).results}

    assert results["calls"].state == "not_tested"
    assert results["calls"].reasons[0].code == "tool_calls_unobservable"
    assert results["arguments"].state == "not_tested"
    assert results["leak"].state == "finding"
    assert results["exfil"].state == "finding"
