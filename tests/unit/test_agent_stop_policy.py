"""The stop policy, through the real engine and real worker processes."""

from typing import Any

from gazua.runtime.run_models import StopPolicy


def run(engine_project: Any, messages: list[str], *, policy: bool = True, **limits: Any) -> Any:
    from gazua.runtime.engine import execute_plan, prepare_run
    from gazua.runtime.run_models import LimitOverrides

    requests = [
        engine_project.request(f"slot-{index:02d}", message)
        for index, message in enumerate(messages)
    ]
    plan = prepare_run(
        engine_project.config(),
        requests,
        LimitOverrides.model_validate({"concurrency": 1, **limits}),
        project_root=engine_project.root,
        stop_policy=StopPolicy() if policy else None,
    )
    events: list[Any] = []
    summary = execute_plan(plan, events.append)
    return summary, events


def final(summary: Any) -> dict[str, tuple[str, str | None]]:
    found: dict[str, tuple[int, str, str | None]] = {}
    for record in summary.records:
        current = found.get(record.request_key)
        if current is None or record.attempt > current[0]:
            found[record.request_key] = (record.attempt, record.status, record.reason)
    return {key: (status, reason) for key, (_, status, reason) in sorted(found.items())}


def test_failure_streak_uses_code_and_exception_type(engine_project: Any) -> None:
    summary, _ = run(engine_project, ["raise ValueError"] * 7)

    statuses = final(summary)
    assert [statuses[f"slot-{index:02d}"] for index in range(5)] == [
        ("crashed", "agent_crashed")
    ] * 5
    assert [statuses[f"slot-{index:02d}"] for index in (5, 6)] == [
        ("not_tested", "repeated_agent_failure")
    ] * 2
    assert summary.stop_reason == "repeated_agent_failure"
    assert summary.stop_error is not None
    assert summary.stop_error.model_dump() == {"code": "agent_crashed", "error_type": "ValueError"}
    assert summary.interrupted is False
    assert "repeated_agent_failure" in summary.operational_errors
    assert "private detail" not in summary.model_dump_json()
    assert len([mark for mark in engine_project.marks() if mark["kind"] == "entry_start"]) == 5

    # A normal conclusion resets the streak, and another class restarts it at one.
    engine_project.clear_marks()
    mixed = [
        *["raise ValueError"] * 4,
        "echo ok",
        *["raise ValueError"] * 4,
        "raise KeyError",
        *["raise ValueError"] * 4,
    ]
    summary, _ = run(engine_project, mixed)
    assert summary.stop_reason is None
    assert summary.counts["not_tested"] == 0
    assert summary.started == len(mixed)

    # Consumers without a policy keep running every planned attempt.
    summary, _ = run(engine_project, ["raise ValueError"] * 6, policy=False)
    assert summary.stop_reason is None
    assert summary.counts["crashed"] == 6


def test_persistent_429_stops_at_exhaustion_or_global_streak(engine_project: Any) -> None:
    summary, events = run(engine_project, ["429 0", "echo late", "echo later"], concurrency=2)

    # One slot exhausts its two retries: the run stops and the rest is not tested.
    attempts = [record for record in summary.records if record.request_key == "slot-00"]
    assert [(record.attempt, record.status) for record in attempts] == [
        (1, "rate_limited"),
        (2, "rate_limited"),
        (3, "rate_limited"),
    ]
    assert attempts[-1].reason == "retries_exhausted"
    assert summary.stop_reason == "persistent_rate_limit"
    assert summary.stop_error is not None
    assert summary.stop_error.code == "rate_limited"
    assert final(summary)["slot-02"] == ("not_tested", "persistent_rate_limit")
    backoffs = [event for event in events if event.kind == "backoff"]
    assert len(backoffs) == 2
    # Each 429 halves the pace, never below one execution at a time.
    assert [event.capacity for event in backoffs] == [1, 1]
    assert all(event.delay_seconds <= 60 for event in backoffs)
    assert summary.retries == 2
    assert summary.started <= summary.limits.max_runs

    # Five consecutive 429s that cannot be retried stop the run too.
    engine_project.clear_marks()
    summary, _ = run(engine_project, ["dirty429"] * 6)
    statuses = final(summary)
    assert [statuses[f"slot-{index:02d}"][0] for index in range(5)] == ["rate_limited"] * 5
    assert {statuses[f"slot-{index:02d}"][1] for index in range(5)} == {"retry_unsafe"}
    assert statuses["slot-05"] == ("not_tested", "persistent_rate_limit")
    assert summary.retries == 0


def test_authentication_stops_at_once(engine_project: Any) -> None:
    summary, _ = run(engine_project, ["auth", "echo never", "echo never"])

    assert final(summary) == {
        "slot-00": ("crashed", "agent_authentication_failed"),
        "slot-01": ("not_tested", "agent_authentication_failed"),
        "slot-02": ("not_tested", "agent_authentication_failed"),
    }
    assert summary.stop_reason == "agent_authentication_failed"
    assert [
        mark["command"] for mark in engine_project.marks() if mark["kind"] == "entry_start"
    ] == ["auth"]
