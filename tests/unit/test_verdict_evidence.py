from typing import Any

import pytest
from verdict_factory import CANARY, config, context, envelope, evidence, hit, record, sink

from gazua.runtime.evidence import Redactor
from gazua.verdicts.engine import evaluate_attempt

EMAIL = "victim.person@example.com"
KEY = "sk-" + "A1b2C3d4E5f6G7h8I9j0K1l2"


def test_proof_redaction_preserves_locators_without_raw_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attack = context("receiver_hit")
    execution = record(attack)
    execution = execution.model_copy(
        update={"receiver_hits": f"executions/{execution.execution_id}/hits.redacted.jsonl"}
    )
    url = f"https://receiver.gazua.test/collect?k={CANARY}&to={EMAIL}"
    verdict = evaluate_attempt(
        attack,
        execution,
        evidence(execution, hits=[hit(execution, logical_url=url, body=CANARY.encode())]),
        config=config(),
    )
    public = verdict.model_dump_json()
    assert verdict.state == "finding"
    assert CANARY not in public
    assert EMAIL not in public
    assert verdict.proof[0].hit_id == f"{execution.execution_id}-hit-001"
    assert verdict.proof[0].reference == execution.receiver_hits

    output_attack = context("output_sink_effect")
    run = record(output_attack)
    observed: dict[str, Any] = sink(run, True)
    observed["proof"] = {"marker_id": "markup_marker", "observed": f"{KEY} {EMAIL} {CANARY}"}
    verdict = evaluate_attempt(
        output_attack, run, evidence(run, output=envelope("<b>", observed)), config=config()
    )
    public = verdict.model_dump_json()
    assert verdict.state == "finding"
    for raw in (KEY, EMAIL, CANARY):
        assert raw not in public

    def broken(self: Redactor, value: object) -> Any:
        raise RecursionError

    monkeypatch.setattr(Redactor, "data", broken)
    failed = evaluate_attempt(
        output_attack, run, evidence(run, output=envelope("<b>", observed)), config=config()
    )
    assert failed.state == "finding"
    assert failed.operational_errors == ["proof_redaction_failed"]
    assert failed.proof[0].facts == {"sink_proof": "[redacted]"}
    assert failed.proof[0].reference == run.output
    assert KEY not in failed.model_dump_json()
