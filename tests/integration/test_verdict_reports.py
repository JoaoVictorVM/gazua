from typing import Any

from report_factory import Scenarios, document, five_states
from verdict_factory import ATTACKER, VICTIM_ORDER, call, context, evidence, record, returns

from gazua.reports.redaction import ReportRedactionPolicy, ReportRedactor
from gazua.reports.storage import document_json, parse_run_document
from gazua.verdicts.engine import VerdictCollector

NUMERIC = (
    "state",
    "severity",
    "planned",
    "evaluated",
    "successes",
    "unknown",
    "not_applicable_count",
    "state_counts",
    "rate",
    "upper_bound",
    "confidence",
    "coverage",
    "gated",
    "low_fidelity",
    "reasons",
    "operational_errors",
)


def partial() -> Scenarios:
    chosen = five_states()
    repeated = context("victim_record_access", "tools", key="tools:idor-02:partial", repetitions=3)
    pairs = list(chosen.pairs)
    for repetition, value in ((1, {"order_id": VICTIM_ORDER, "user_id": "victim-1"}), (2, None)):
        execution = record(repeated, repetition)
        calls = [call(1, "get_order", arguments={"order_id": VICTIM_ORDER}, actor=ATTACKER)]
        pairs.append(
            (
                execution,
                evidence(
                    execution,
                    calls=calls,
                    channel=returns(execution.execution_id, calls, {1: value}),
                ),
            )
        )
    pairs.append((record(repeated, 3, status="skipped_by_limit", reason="max_runs"), None))
    return Scenarios(chosen.configuration, [*chosen.contexts, repeated], pairs)


def native(chosen: Scenarios) -> Any:
    collector = VerdictCollector(chosen.contexts, chosen.configuration)
    for execution, private in chosen.pairs:
        if private is not None:
            collector(execution, private)
    from verdict_factory import summary

    return collector.finalize(summary(chosen.records()))


def test_native_rates_bounds_states_and_gates_are_unchanged() -> None:
    chosen = partial()
    expected = native(chosen)
    treatment = ReportRedactor(ReportRedactionPolicy.from_config(chosen.configuration))

    built = parse_run_document(document_json(document(chosen, treatment=treatment)).encode())

    assert built.verdicts.has_gated_findings == expected.has_gated_findings
    assert built.verdicts.counts_by_damage == expected.counts_by_damage
    for mine, theirs in zip(built.verdicts.results, expected.results, strict=True):
        for name in NUMERIC:
            assert getattr(mine, name) == getattr(theirs, name), name
        assert len(mine.proof) == len(theirs.proof)
    shown = {item.attack_key: item for item in built.verdicts.results}["tools:idor-02:partial"]
    assert shown.coverage == "partial"
    assert shown.rate == 0.5
    assert shown.upper_bound is not None
    missing = {item.attack_key: item for item in built.verdicts.results}[
        "tools:permission-03:waiting"
    ]
    assert missing.rate is None
    assert missing.upper_bound is None


def test_statistics_failure_keeps_null_bound() -> None:
    built = document()
    result = built.verdicts.results[0]
    failed = result.model_copy(
        update={"upper_bound": None, "operational_errors": ["statistics_error"]}
    )
    data = built.model_dump(mode="json")
    data["verdicts"]["results"][0] = failed.model_dump(mode="json")

    again = parse_run_document(__import__("json").dumps(data).encode())

    assert again.verdicts.results[0].upper_bound is None
    assert again.verdicts.results[0].rate == result.rate
