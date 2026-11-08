import threading
import time
from decimal import Decimal

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from gazua.runtime.budget import (
    Admission,
    Capacity,
    RunBudget,
    backoff_delay,
    decimal_text,
    retry_refusal,
    to_decimal,
    wait_cancelable,
)


def budget(**overrides: object) -> RunBudget:
    values: dict[str, object] = {
        "max_runs": 300,
        "max_cost": None,
        "cost_per_run": None,
        "source": "unavailable",
    }
    values.update(overrides)
    return RunBudget(**values)  # type: ignore[arg-type]


def test_reservations_never_exceed_max_runs() -> None:
    shared = budget(max_runs=100)
    granted: list[Admission] = []
    lock = threading.Lock()

    def reserve_many() -> None:
        for _ in range(60):
            result = shared.reserve()
            if isinstance(result, Admission):
                with lock:
                    granted.append(result)
            else:
                assert result == "max_runs"

    threads = [threading.Thread(target=reserve_many) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(granted) == 100
    assert sorted(item.number for item in granted) == list(range(1, 101))
    assert shared.started == 100
    assert shared.reserve() == "max_runs"


@settings(max_examples=60, deadline=None)
@given(
    max_runs=st.integers(1, 30),
    plan=st.lists(st.sampled_from(["first", "retry", "finish", "cancel"]), max_size=80),
)
def test_started_slots_never_exceed_max_runs_for_any_order(max_runs: int, plan: list[str]) -> None:
    shared = budget(max_runs=max_runs)
    for step in plan:
        if step in ("first", "retry"):
            shared.reserve()
    assert shared.started <= max_runs
    assert shared.started == min(max_runs, sum(step in ("first", "retry") for step in plan))


def test_decimal_budget_distinguishes_estimated_reported_and_unknown() -> None:
    estimated = budget(max_cost=to_decimal(0.3), cost_per_run=to_decimal(0.1), source="estimated")
    results = [estimated.reserve() for _ in range(4)]
    # 0.1 + 0.1 + 0.1 is exactly 0.3 in decimal, so the third attempt still fits.
    assert [isinstance(item, Admission) for item in results] == [True, True, True, False]
    assert results[3] == "max_cost"
    assert estimated.reserved == Decimal("0.3")
    # Observed usage is shown apart and never double counted against the estimate.
    assert estimated.record_usage("u1", Decimal("5"))
    assert not estimated.reported_exhausted
    assert estimated.reserved == Decimal("0.3")

    reported = budget(max_cost=to_decimal(1), source="reported")
    assert isinstance(reported.reserve(), Admission)
    assert reported.record_usage("u1", Decimal("0.6"))
    assert not reported.record_usage("u1", Decimal("0.6"))
    assert reported.reported == Decimal("0.6")
    assert not reported.reported_exhausted
    assert reported.record_usage("u2", Decimal("0.4"))
    assert reported.reported_exhausted
    assert reported.reserve() == "max_cost"

    unknown = budget(max_cost=to_decimal(0.01), source="unavailable", max_runs=3)
    # Without usage or estimate, max_cost cannot stop anything and missing cost is not zero.
    assert [isinstance(unknown.reserve(), Admission) for _ in range(4)] == [True, True, True, False]
    assert unknown.reported == Decimal(0)
    assert not unknown.reported_exhausted

    free = budget(max_cost=to_decimal(1), cost_per_run=to_decimal(0), source="estimated")
    assert all(isinstance(free.reserve(), Admission) for _ in range(10))

    assert decimal_text(Decimal("0.30")) == "0.3"
    assert decimal_text(to_decimal(1e-05)) == "0.00001"
    assert decimal_text(Decimal("2")) == "2"
    for invalid in (-1, float("inf"), float("nan")):
        with pytest.raises(ValueError, match=r"decimal|finite"):
            to_decimal(invalid)


@settings(max_examples=60, deadline=None)
@given(st.lists(st.tuples(st.sampled_from("abcdef"), st.integers(0, 10**6)), max_size=40))
def test_duplicate_usage_never_duplicates_cost(increments: list[tuple[str, int]]) -> None:
    shared = budget(source="reported")
    expected: dict[str, Decimal] = {}
    for usage_id, cents in increments:
        value = Decimal(cents) / 100
        shared.record_usage(usage_id, value)
        expected.setdefault(usage_id, value)
    assert shared.reported == sum(expected.values(), Decimal(0))


def test_429_halves_capacity_and_bounds_cancelable_backoff() -> None:
    capacity = Capacity(5)
    assert [capacity.halve() for _ in range(4)] == [2, 1, 1, 1]
    assert Capacity(0).value == 1

    assert backoff_delay(0, None) == 1.0
    assert backoff_delay(1, None) == 2.0
    assert backoff_delay(5, None) == 2.0
    assert backoff_delay(0, 7.5) == 7.5
    assert backoff_delay(0, 0) == 0
    assert backoff_delay(0, 3600) == 60.0
    assert backoff_delay(0, float("inf")) == 1.0
    assert backoff_delay(1, -3) == 2.0

    assert retry_refusal(attempt=1, max_retries=2, real_tool_called=False, has_reset=False) is None
    assert retry_refusal(attempt=2, max_retries=2, real_tool_called=False, has_reset=False) is None
    assert (
        retry_refusal(attempt=3, max_retries=2, real_tool_called=False, has_reset=False)
        == "retries_exhausted"
    )
    assert (
        retry_refusal(attempt=1, max_retries=2, real_tool_called=True, has_reset=False)
        == "retry_unsafe"
    )
    assert retry_refusal(attempt=1, max_retries=2, real_tool_called=True, has_reset=True) is None

    cancel = threading.Event()
    threading.Timer(0.05, cancel.set).start()
    started = time.monotonic()
    assert wait_cancelable(30, cancel) is False
    assert time.monotonic() - started < 5
    assert wait_cancelable(0.01, threading.Event()) is True
