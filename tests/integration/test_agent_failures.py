from typing import Any

from gazua.modes.agent import AUTHENTICATION_MESSAGE, stop_message


def statuses(result: Any) -> list[tuple[str, str | None]]:
    return [(record.status, record.reason) for record in result.engine.records]


def test_auth_failure_stops_admission_and_runs_final_reset(agent_project: Any) -> None:
    agent_project.write(legit_tasks=[], target={"reset": "agent_target:reset"})
    agent_project.behave("auth")

    result = agent_project.run(molds=("secret-04", "spending-03"), repetitions=3)

    assert result.engine.stop_reason == "agent_authentication_failed"
    assert stop_message(result.engine) == AUTHENTICATION_MESSAGE
    assert statuses(result)[0] == ("crashed", "agent_authentication_failed")
    assert set(statuses(result)[1:]) == {("not_tested", "agent_authentication_failed")}
    assert len(result.engine.records) == 6
    assert result.engine.cleanup == "succeeded"
    assert result.engine.interrupted is False
    assert result.exit_code == 2
    calls = [item for item in agent_project.effects() if item["kind"] == "entrypoint_called"]
    assert len(calls) == 1
    assert all(item.state == "not_tested" for item in result.verdicts.results)


def test_five_identical_failures_close_admission(agent_project: Any) -> None:
    agent_project.write(legit_tasks=[])
    agent_project.behave("crash")

    result = agent_project.run(molds=("secret-04", "spending-03"))

    assert result.engine.stop_reason == "repeated_agent_failure"
    error = result.engine.stop_error
    assert error is not None
    assert (error.code, error.error_type) == ("agent_crashed", "ValueError")
    crashed = [item for item in statuses(result) if item[0] == "crashed"]
    assert len(crashed) == 5
    assert statuses(result).count(("not_tested", "repeated_agent_failure")) == 5
    message = stop_message(result.engine)
    assert message is not None
    assert "ValueError" in message
    assert "GAZUA-CANARY" not in result.engine.model_dump_json()
    assert result.engine.interrupted is False
    assert result.exit_code == 2


def test_429_slows_then_marks_remainder_not_tested(agent_project: Any) -> None:
    agent_project.write(legit_tasks=[])
    agent_project.behave("rate_limit")

    events: list[Any] = []
    result = agent_project.run(
        molds=("secret-04", "spending-03"), overrides={"concurrency": 2}, on_event=events.append
    )

    assert result.engine.stop_reason == "persistent_rate_limit"
    backoffs = [event for event in events if event.kind == "backoff"]
    assert backoffs
    assert backoffs[-1].capacity == 1
    assert result.engine.retries == len(backoffs)
    assert result.engine.started <= result.engine.limits.max_runs
    assert ("not_tested", "persistent_rate_limit") in statuses(result)
    assert all(item.state == "not_tested" for item in result.verdicts.results)
    assert all(item.state_counts.resisted == 0 for item in result.verdicts.results)
    assert result.exit_code == 2
