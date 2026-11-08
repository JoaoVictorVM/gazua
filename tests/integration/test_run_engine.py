import json
import threading
import time
from collections import defaultdict
from typing import Any

from gazua.runtime.run_models import (
    BackoffStarted,
    ExecutionFinished,
    ExecutionRecord,
    ExecutionStarted,
    RunEvent,
    RunPrepared,
    RunSummary,
)


def records_of(events: list[RunEvent]) -> list[ExecutionRecord]:
    return [event.record for event in events if isinstance(event, ExecutionFinished)]


def by_key(summary: RunSummary) -> dict[str, ExecutionRecord]:
    return {record.request_key: record for record in summary.records}


def intervals(marks: list[dict[str, Any]]) -> list[tuple[float, float]]:
    starts = {mark["pid"]: mark["t"] for mark in marks if mark["kind"] == "entry_start"}
    ends = {mark["pid"]: mark["t"] for mark in marks if mark["kind"] == "entry_end"}
    return sorted((starts[pid], ends[pid]) for pid in starts if pid in ends)


def max_overlap(spans: list[tuple[float, float]]) -> int:
    points = sorted([(start, 1) for start, _ in spans] + [(end, -1) for _, end in spans])
    current = peak = 0
    for _, step in points:
        current += step
        peak = max(peak, current)
    return peak


def test_summary_precedes_first_attack(engine_project: Any) -> None:
    seen: dict[str, Any] = {}

    def on_event(event: RunEvent) -> None:
        if isinstance(event, RunPrepared):
            seen["lines"] = event.lines()
            seen["marks_at_prepared"] = engine_project.marks()
            time.sleep(0.5)
            seen["released_at"] = time.time()
        if isinstance(event, ExecutionStarted):
            seen.setdefault("first_started_seq", event.seq)

    requests = [engine_project.request(f"m{index}-1", "echo hi") for index in range(3)]
    from gazua.runtime.engine import execute_plan, prepare_run

    plan = prepare_run(engine_project.config(), requests, project_root=engine_project.root)
    summary = execute_plan(plan, on_event)

    assert seen["lines"][0] == (
        "Running 3 executions: 3 molds x 1 repetition. Limit 300. 1 real tool, 1 in dry-run."
    )
    assert seen["marks_at_prepared"] == []
    marks = engine_project.marks()
    first_attack = min(mark["t"] for mark in marks if mark["kind"] == "entry_start")
    assert first_attack > seen["released_at"]
    assert seen["first_started_seq"] == 2
    assert summary.counts["completed"] == 3


def test_225_planned_with_max_runs_100_starts_exactly_100(engine_project: Any) -> None:
    requests = [
        engine_project.request(f"mold{mold:02d}-{repetition}", "echo x", repetition=repetition)
        for mold in range(45)
        for repetition in range(1, 6)
    ]
    prepared: list[RunPrepared] = []

    summary, events = engine_project.run(requests, {"max_runs": 100, "concurrency": 8})
    prepared = [event for event in events if isinstance(event, RunPrepared)]

    assert (
        prepared[0]
        .lines()[0]
        .startswith("Running 225 executions: 45 molds x 5 repetitions. Limit 100.")
    )
    assert summary.planned == 225
    assert summary.started == 100
    assert summary.counts["completed"] == 100
    assert summary.counts["skipped_by_limit"] == 125
    skipped = [record for record in summary.records if record.status == "skipped_by_limit"]
    assert {record.reason for record in skipped} == {"max_runs"}
    assert all(record.started_at is None for record in skipped)
    assert not any(record.evidence_complete for record in skipped)
    starts = [mark for mark in engine_project.marks() if mark["kind"] == "entry_start"]
    assert len(starts) == 100
    assert len(summary.records) == 225


def test_timeout_and_crash_do_not_stop_next_execution(engine_project: Any) -> None:
    descendant = engine_project.root / "descendant.txt"
    requests = [
        engine_project.request("hang-1", "sleep"),
        engine_project.request("crash-1", "crash"),
        engine_project.request("tree-1", f"spawn {descendant}"),
        engine_project.request("after-1", "echo still running"),
    ]

    started = time.monotonic()
    summary, _ = engine_project.run(requests, {"timeout": 3, "concurrency": 1})

    records = by_key(summary)
    assert (records["hang-1"].status, records["hang-1"].reason) == ("timed_out", "attack_timeout")
    assert records["hang-1"].duration_ms >= 3000
    assert (records["crash-1"].status, records["crash-1"].reason) == ("crashed", "agent_crashed")
    assert records["crash-1"].exit_code == 3
    assert records["tree-1"].status == "timed_out"
    assert records["after-1"].status == "completed"
    assert time.monotonic() - started < 60
    stopped_at = descendant.stat().st_size
    time.sleep(0.5)
    assert descendant.stat().st_size == stopped_at
    output = summary.records[-1].output
    assert output is not None
    engine = engine_project.root / ".gazua" / "runs" / summary.run_id / "engine"
    assert json.loads((engine / output).read_text()) == "echo still running"


def test_concurrency_is_two_without_reset_and_one_with_reset(engine_project: Any) -> None:
    requests = [engine_project.request(f"hold{index}-1", "hold 1.5") for index in range(4)]

    free, free_events = engine_project.run(requests)
    free_spans = intervals(engine_project.marks())
    (engine_project.root / "marks.jsonl").unlink()
    serialized, serialized_events = engine_project.run(
        requests, config=engine_project.config(reset=True)
    )
    serialized_spans = intervals(engine_project.marks())

    assert free.effective_concurrency == 2
    assert max_overlap(free_spans) == 2
    assert serialized.requested_concurrency == 2
    assert serialized.effective_concurrency == 1
    assert max_overlap(serialized_spans) == 1
    prepared = next(event for event in serialized_events if isinstance(event, RunPrepared))
    assert "Concurrency 1 (requested 2, target.reset runs one at a time)." in prepared.lines()
    assert next(e for e in free_events if isinstance(e, RunPrepared)).lines()[1] == "Concurrency 2."


def test_retry_consumes_global_slot_and_never_repeats_dirty_tool_effect(
    engine_project: Any,
) -> None:
    requests = [
        engine_project.request("limited-1", "429 0"),
        engine_project.request("dirty-1", "dirty429"),
        engine_project.request("later-1", "echo late"),
    ]

    summary, events = engine_project.run(requests, {"max_runs": 4, "concurrency": 1})

    attempts: dict[str, list[ExecutionRecord]] = defaultdict(list)
    for record in summary.records:
        attempts[record.request_key].append(record)
    assert [record.attempt for record in attempts["limited-1"]] == [1, 2, 3]
    assert [record.reason for record in attempts["limited-1"]] == [
        "rate_limited",
        "rate_limited",
        "retries_exhausted",
    ]
    assert len({record.execution_id for record in attempts["limited-1"]}) == 3
    (dirty,) = attempts["dirty-1"]
    assert (dirty.status, dirty.reason) == ("rate_limited", "retry_unsafe")
    effects = [mark for mark in engine_project.marks() if mark["kind"] == "tool_effect"]
    assert [mark["id"] for mark in effects] == ["GAZUA-dirty"]
    (later,) = attempts["later-1"]
    assert (later.status, later.reason) == ("skipped_by_limit", "max_runs")
    assert summary.started == 4
    assert summary.retries == 2
    backoffs = [event for event in events if isinstance(event, BackoffStarted)]
    assert [event.request_key for event in backoffs] == ["limited-1", "limited-1"]
    assert backoffs[-1].capacity == 1


def test_final_record_exists_once_for_every_planned_request(engine_project: Any) -> None:
    cancel = threading.Event()
    finished: list[str] = []

    def on_event(event: RunEvent) -> None:
        if isinstance(event, ExecutionFinished) and event.record.status == "completed":
            finished.append(event.record.request_key)
            if len(finished) == 2:
                cancel.set()

    requests = [
        engine_project.request("a-1", "echo a"),
        engine_project.request("b-1", "429 0"),
        engine_project.request("c-1", "echo c"),
        engine_project.request("d-1", "hold 30"),
        engine_project.request("e-1", "echo e"),
        engine_project.request("f-1", "crash"),
    ]
    from gazua.runtime.engine import execute_plan, prepare_run

    plan = prepare_run(engine_project.config(), requests, project_root=engine_project.root)
    summary = execute_plan(plan, on_event, cancel=cancel)

    assert summary.interrupted
    grouped: dict[str, list[ExecutionRecord]] = defaultdict(list)
    for record in summary.records:
        grouped[record.request_key].append(record)
    assert set(grouped) == {request.key for request in requests}
    for records in grouped.values():
        assert [record.attempt for record in records] == list(range(1, len(records) + 1))
    assert len({record.execution_id for record in summary.records}) == len(summary.records)
    assert {grouped["d-1"][-1].status, grouped["e-1"][-1].status} <= {"cancelled", "not_tested"}
    engine = engine_project.root / ".gazua" / "runs" / summary.run_id / "engine"
    stored = sorted(engine.glob("executions/*/execution.json"))
    assert len(stored) == len(summary.records)
    assert RunSummary.model_validate_json((engine / "summary.json").read_text()) == summary
    assert not (engine / "private").exists()
