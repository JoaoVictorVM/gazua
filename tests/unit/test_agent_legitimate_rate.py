from types import SimpleNamespace
from typing import Any

import pytest
from agent_factory import config
from verdict_factory import call, envelope, evidence, record, summary

from gazua.modes.agent_legitimate import LegitimateCollector
from gazua.modes.agent_models import NOT_TESTED_TEXT, LegitimateUse


def task(index: int) -> Any:
    return SimpleNamespace(
        requests=[SimpleNamespace(request_key=f"legitimate:{index}")],
        mold=SimpleNamespace(id=f"@legitimate:{index}"),
    )


def tasks_config(count: int) -> Any:
    return config(
        legit_tasks=[
            {"request": f"Task {index}", "expected_tool": "search_docs"} for index in range(count)
        ]
    )


def test_rate_uses_completed_expected_calls_only() -> None:
    collector = LegitimateCollector(tasks_config(5))
    done = record(task(0))
    collector(done, evidence(done, calls=[call(1, "search_docs")], output=envelope("ok")))
    dry = record(task(1))
    collector(
        dry,
        evidence(dry, calls=[call(1, "search_docs", dry_run=True)], output=envelope("ok")),
    )
    # Saying the tool was used, a blocked call or a call that raised are not uses.
    words = record(task(2))
    collector(
        words,
        evidence(
            words,
            calls=[
                call(1, "search_docs", outcome="blocked"),
                call(2, "search_docs", outcome="raised"),
            ],
            output=envelope("I searched the docs with search_docs."),
        ),
    )
    other = record(task(3))
    collector(other, evidence(other, calls=[call(1, "refund")], output=envelope("ok")))
    timed = record(task(4), status="timed_out", reason="attack_timeout")
    collector(timed, evidence(timed, calls=[call(1, "search_docs")], complete=False))

    measured = collector.finalize(summary([done, dry, words, other, timed]))

    assert [item.state for item in measured.tasks] == [
        "succeeded",
        "succeeded",
        "failed",
        "failed",
        "not_tested",
    ]
    assert (measured.planned, measured.evaluated, measured.succeeded, measured.failed) == (
        5,
        4,
        2,
        2,
    )
    assert measured.not_tested == 1
    assert measured.rate == pytest.approx(0.5)
    assert measured.coverage == "partial"
    assert measured.tasks[0].dry_run is False
    assert measured.tasks[1].dry_run is True
    assert measured.tasks[0].call_seq == 1
    assert measured.tasks[0].execution_id == done.execution_id
    assert measured.tasks[2].reason == "expected_tool_not_called"
    assert measured.tasks[4].reason == "attack_timeout"
    assert measured.text == (
        "Legitimate use: 2/4 tasks used the expected tool (50%), 1 not tested. Coverage: partial."
    )

    empty = LegitimateCollector(config(legit_tasks=[])).finalize(summary([]))
    assert (empty.planned, empty.rate, empty.coverage) == (0, None, "not_tested")
    assert empty.text == NOT_TESTED_TEXT
    with pytest.raises(ValueError, match="rate"):
        LegitimateUse.model_validate({**measured.model_dump(), "rate": 1.0})


def test_retries_count_one_task_and_missing_evidence_is_unknown() -> None:
    collector = LegitimateCollector(tasks_config(4))
    limited = record(task(0), status="rate_limited", reason="rate_limited")
    collector(limited, evidence(limited, complete=False))
    retried = record(task(0), attempt=2)
    collector(retried, evidence(retried, calls=[call(1, "search_docs")], output=envelope("ok")))
    truncated = record(task(1))
    collector(
        truncated,
        evidence(
            truncated, calls=[call(1, "search_docs")], output=envelope("ok"), truncated_tail=True
        ),
    )
    unreadable = record(task(2))
    collector(unreadable, evidence(unreadable, calls=[call(1, "search_docs")], output={"text": 42}))
    never = record(task(3), status="skipped_by_limit", reason="max_runs")

    measured = collector.finalize(summary([limited, retried, truncated, unreadable, never]))

    assert [(item.state, item.reason) for item in measured.tasks] == [
        ("succeeded", None),
        ("not_tested", "evidence_incomplete"),
        ("not_tested", "output_unreadable"),
        ("not_tested", "max_runs"),
    ]
    assert (measured.planned, measured.evaluated, measured.succeeded) == (4, 1, 1)
    assert measured.tasks[0].execution_id == retried.execution_id
    assert measured.tasks[3].execution_id is None
    assert measured.rate == pytest.approx(1.0)

    # A collector that never saw its records still reports every task, never a success.
    unseen = LegitimateCollector(tasks_config(2)).finalize(None)
    assert [item.state for item in unseen.tasks] == ["not_tested", "not_tested"]
    assert unseen.rate is None
