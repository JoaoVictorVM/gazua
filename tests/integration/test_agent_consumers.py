"""Minimal later consumers of agent mode: they read its contracts, never its terminal output."""

from typing import Any

from gazua.modes.agent_models import AgentResult
from gazua.reports.builder import PlainTreatment, build_run_document
from gazua.reports.models import RunDocument


def document_of(result: AgentResult) -> RunDocument:
    return build_run_document(
        run_id=result.run_id,
        created_at="2026-01-01T00:00:00.000000Z",
        target_ref="agent_target:entrypoint",
        mode="agent",
        language="en",
        engine=result.engine,
        verdicts=result.verdicts,
        contexts=result.contexts,
        reproduction=result.reproduction,
        treatment=PlainTreatment(),
        exit_code=result.exit_code,
        legitimate_use=result.legitimate_use,
    )


def rates(result: AgentResult) -> dict[str, tuple[float | None, float | None, int]]:
    return {
        item.mold_id: (item.rate, item.upper_bound, item.evaluated)
        for item in result.verdicts.results
    }


def test_demo_consumer_can_use_agent_result_and_run_document(agent_project: Any) -> None:
    result = agent_project.run(molds=("secret-04", "spending-03"), repetitions=2)

    copied = AgentResult.model_validate_json(result.model_dump_json())
    assert copied == result
    document = RunDocument.model_validate_json(document_of(result).model_dump_json())
    findings = {item.mold_id: item for item in document.findings}
    assert set(findings) == {"secret-04", "spending-03"}
    for finding in document.findings:
        assert finding.mode == "agent"
        assert finding.proof_ids
        assert finding.reproduction.argv[:3] == ["gazua", "run", "--agent"]
    assert document.legitimate_use == result.legitimate_use
    # A model reported by the target is optional; an absent one stays absent.
    assert document.metadata.model is None


def test_defense_consumer_gets_attack_and_legitimate_rates(agent_project: Any) -> None:
    before = agent_project.run(molds=("secret-04",), repetitions=2)
    agent_project.behave("hardened")
    after = agent_project.run(molds=("secret-04",), repetitions=2)

    table = {
        "before": (rates(before), before.legitimate_use.rate),
        "after": (rates(after), after.legitimate_use.rate),
    }
    assert table["before"][0]["secret-04"][0] == 1.0
    assert table["after"][0]["secret-04"][0] == 0.0
    assert table["after"][0]["secret-04"][1] is not None
    # The defended agent still uses its tool for the legitimate task.
    assert table["before"][1] == 1.0
    assert table["after"][1] == 1.0
