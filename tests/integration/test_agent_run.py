from typing import Any

import pytest

from gazua.verdicts.statistics import upper_bound


def result_of(result: Any, mold_id: str) -> Any:
    [found] = [item for item in result.verdicts.results if item.mold_id == mold_id]
    return found


def test_agent_rates_use_engine_attempt_records(agent_project: Any) -> None:
    agent_project.write(legit_tasks=[])
    agent_project.behave("flaky")
    flaky = agent_project.run(mold="secret-04")

    secret = result_of(flaky, "secret-04")
    assert (secret.state, secret.successes, secret.evaluated, secret.planned) == (
        "finding",
        1,
        5,
        5,
    )
    assert secret.rate == pytest.approx(0.2)
    assert secret.upper_bound == pytest.approx(upper_bound(1, 5, 0.95))
    assert len(secret.proof) == 1
    executions = {record.execution_id for record in flaky.engine.records}
    assert secret.proof[0].execution_id in executions
    assert flaky.exit_code == 1

    agent_project.behave("hardened")
    hardened = agent_project.run(mold="secret-04")
    resisted = result_of(hardened, "secret-04")
    assert (resisted.state, resisted.successes, resisted.evaluated) == ("resisted", 0, 5)
    assert resisted.upper_bound == pytest.approx(0.45, abs=0.01)
    assert hardened.exit_code == 0

    # Executions that never ran, or crashed, are never counted as resisted.
    limited = agent_project.run(mold="secret-04", overrides={"max_runs": 3})
    partial = result_of(limited, "secret-04")
    assert (partial.evaluated, partial.unknown, partial.coverage) == (3, 2, "partial")
    assert partial.state_counts.not_tested == 2
    agent_project.behave("other_crash")
    crashed = agent_project.run(mold="secret-04", repetitions=2)
    failed = result_of(crashed, "secret-04")
    assert failed.state == "not_tested"
    assert failed.state_counts.resisted == 0
    assert crashed.exit_code == 2
