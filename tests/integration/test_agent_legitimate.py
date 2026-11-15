import json
from typing import Any

import pytest

from gazua.modes.agent_models import NOT_TESTED_TEXT
from gazua.reports.builder import build_run_document
from gazua.reports.redaction import ReportRedactionPolicy, ReportRedactor
from gazua.reports.rendering import render_report, terminal_lines

TASKS = [
    {"request": "What is the refund policy?", "expected_tool": "search_docs"},
    {"request": "Tell me a joke.", "expected_tool": "search_docs"},
]


def document_of(agent_project: Any, result: Any) -> Any:
    from gazua.config.loader import load_config

    config = load_config(agent_project.root / "gazua.yaml").config
    redactor = ReportRedactor(ReportRedactionPolicy.from_config(config))
    return build_run_document(
        run_id=result.run_id,
        created_at="2026-01-01T00:00:00.000000Z",
        target_ref=config.entrypoint,
        mode="agent",
        language="en",
        engine=result.engine,
        verdicts=result.verdicts,
        contexts=result.contexts,
        reproduction=result.reproduction,
        treatment=redactor,
        exit_code=result.exit_code,
        config=config,
        legitimate_use=result.legitimate_use,
    )


def test_configured_tasks_share_budget_and_appear_as_rate(agent_project: Any) -> None:
    agent_project.write(legit_tasks=TASKS)
    agent_project.behave("hardened")

    result = agent_project.run(mold="secret-04", overrides={"max_runs": 6})

    calls = [item for item in agent_project.effects() if item["kind"] == "entrypoint_called"]
    # The tasks run first, in declared order, through the same entrypoint.
    assert [item["message"] for item in calls[:2]] == [task["request"] for task in TASKS]
    assert len(calls) == 6
    measured = result.legitimate_use
    assert [task.state for task in measured.tasks] == ["succeeded", "failed"]
    assert (measured.planned, measured.evaluated, measured.succeeded) == (2, 2, 1)
    assert measured.rate == pytest.approx(0.5)
    assert measured.coverage == "complete"
    # Tasks and attacks share max_runs: four attack repetitions ran, one was not.
    [secret] = result.verdicts.results
    assert (secret.evaluated, secret.state_counts.not_tested) == (4, 1)
    assert result.engine.started == 6
    legit_keys = {"legitimate:0", "legitimate:1"}
    assert legit_keys <= {record.request_key for record in result.engine.records}
    assert not legit_keys & {slot.request_key for c in result.contexts for slot in c.requests}
    # The failed task is functional: it creates no finding and does not change the gate.
    assert result.exit_code == 0

    document = document_of(agent_project, result)
    assert document.legitimate_use == measured
    stored = json.loads(document.model_dump_json())
    assert stored["legitimate_use"]["rate"] == pytest.approx(0.5)
    assert "Tell me a joke." not in document.model_dump_json()


def test_no_tasks_prints_not_tested_in_all_reports(agent_project: Any) -> None:
    agent_project.write(legit_tasks=[])

    result = agent_project.run(mold="secret-04", repetitions=1)

    assert result.legitimate_use.planned == 0
    document = document_of(agent_project, result)
    html, markdown = render_report(document)
    terminal = terminal_lines(document)
    assert NOT_TESTED_TEXT == "Legitimate use: not tested"
    assert NOT_TESTED_TEXT in terminal
    assert NOT_TESTED_TEXT in markdown.splitlines()
    assert f'<p class="legitimate">{NOT_TESTED_TEXT}</p>' in html
    stored = json.loads(document.model_dump_json())
    assert stored["legitimate_use"]["rate"] is None
    assert stored["legitimate_use"]["coverage"] == "not_tested"
