import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from agent_factory import agent_molds, config
from hypothesis import given, settings
from hypothesis import strategies as st
from verdict_factory import call, envelope, evidence, record, summary

from gazua.modes.agent_legitimate import LegitimateCollector
from gazua.modes.agent_plan import quick_selection
from gazua.runtime.run_models import StopPolicy

STATUSES = ("completed", "crashed", "timed_out", "rate_limited", "skipped_by_limit")


@settings(max_examples=60, deadline=None)
@given(st.permutations(list(range(15))), st.integers(min_value=1, max_value=20))
def test_quick_selection_is_stable_bounded_and_diverse(order: list[int], limit: int) -> None:
    molds = list(agent_molds())
    shuffled = [molds[index] for index in order]

    chosen = quick_selection(shuffled, limit)

    assert [item.id for item in chosen] == [item.id for item in quick_selection(molds, limit)]
    assert len(chosen) == min(limit, len(molds))
    assert len({item.id for item in chosen}) == len(chosen)
    damages = [item.damage for item in chosen]
    distinct = len({item.damage for item in molds})
    assert len(set(damages[:distinct])) == min(len(chosen), distinct)


def legit_task(index: int) -> Any:
    return SimpleNamespace(
        requests=[SimpleNamespace(request_key=f"legitimate:{index}")],
        mold=SimpleNamespace(id=f"@legitimate:{index}"),
    )


attempts = st.lists(st.tuples(st.sampled_from(STATUSES), st.booleans()), min_size=0, max_size=3)


@settings(max_examples=80, deadline=None)
@given(st.lists(attempts, min_size=0, max_size=4), st.randoms())
def test_every_task_gets_one_terminal_and_counts_stay_valid(
    plans: list[list[tuple[str, bool]]], random: Any
) -> None:
    configuration = config(
        legit_tasks=[
            {"request": f"Task {index}", "expected_tool": "search_docs"}
            for index in range(len(plans))
        ]
    )
    collector = LegitimateCollector(configuration)
    records = []
    deliveries = []
    for index, tries in enumerate(plans):
        for attempt, (status, called) in enumerate(tries, start=1):
            item = record(legit_task(index), attempt=attempt, status=status)
            records.append(item)
            calls = [call(1, "search_docs")] if called else []
            deliveries.append((item, evidence(item, calls=calls, output=envelope("ok"))))
    random.shuffle(deliveries)
    for item, captured in deliveries:
        collector(item, captured)

    measured = collector.finalize(summary(records))

    assert measured.planned == len(plans)
    assert measured.planned == measured.evaluated + measured.not_tested
    assert [task.task_index for task in measured.tasks] == list(range(len(plans)))
    for task, tries in zip(measured.tasks, plans, strict=True):
        if not tries:
            assert task.state == "not_tested"
            continue
        status, called = tries[-1]
        if status != "completed":
            assert task.state == "not_tested"
        else:
            assert task.state == ("succeeded" if called else "failed")
    if measured.rate is not None:
        assert 0 <= measured.rate <= 1


def stop_after(outcomes: list[tuple[str, str | None, str | None]]) -> int | None:
    """The 1-based conclusion at which the engine's policy stops, through its own method."""
    from gazua.runtime.engine import _Outcome, _Run, prepare_run  # pyright: ignore[reportPrivateUsage]
    from gazua.runtime.run_models import ExecutionRequest

    request = ExecutionRequest.model_validate(
        {
            "key": "slot",
            "mold_id": "slot",
            "repetition": 1,
            "mode": "agent",
            "executor": "consumer:execute",
            "payload": {},
            "requires_receiver": False,
            "receiver_transport": False,
            "usage_reporting": False,
        }
    )
    with tempfile.TemporaryDirectory() as folder:
        plan = prepare_run(config(), [request], project_root=Path(folder), stop_policy=StopPolicy())
        run = _Run(plan, None, None, None)
        for number, (status, reason, error_type) in enumerate(outcomes, start=1):
            result = {"status": "error", "error_type": error_type}
            stop = run.observe_conclusion(_Outcome(status, reason), result)  # type: ignore[arg-type]
            if stop is not None:
                return number
    return None


failures = st.sampled_from(
    [
        ("completed", None, None),
        ("crashed", "agent_crashed", "ValueError"),
        ("crashed", "agent_crashed", "KeyError"),
        ("timed_out", "attack_timeout", None),
        ("cancelled", "interrupted", None),
    ]
)


@settings(max_examples=60, deadline=None)
@given(st.lists(failures, max_size=20))
def test_stop_follows_the_observed_sequence(outcomes: list[Any]) -> None:
    expected: int | None = None
    previous, count = None, 0
    for number, (status, reason, error_type) in enumerate(outcomes, start=1):
        if status == "cancelled":
            continue
        if status == "completed":
            previous, count = None, 0
            continue
        fingerprint = (reason, error_type if status == "crashed" else None)
        count = count + 1 if fingerprint == previous else 1
        previous = fingerprint
        if count >= 5:
            expected = number
            break

    assert stop_after(outcomes) == expected
