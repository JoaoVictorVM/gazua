import json
from pathlib import Path
from typing import Any

import pytest

from gazua.mcp.evidence import DeliveryLog, read_delivery_channel

EXECUTION = "GAZUA-exec-0001"


def delivery(order: int, injection: str = "k#turn1", **overrides: Any) -> dict[str, Any]:
    event: dict[str, Any] = {
        "schema_version": 1,
        "kind": "delivery",
        "execution_id": EXECUTION,
        "order": order,
        "injection_id": injection,
        "turn": 1,
        "tool": "search_docs",
        "surface": "description",
        "delivered": True,
        "reason": None,
        "call_seq": None,
    }
    event.update(overrides)
    return event


def call(order: int, seq: int, **overrides: Any) -> dict[str, Any]:
    event: dict[str, Any] = {
        "schema_version": 1,
        "kind": "call",
        "execution_id": EXECUTION,
        "order": order,
        "call_seq": seq,
    }
    event.update(overrides)
    return event


def write(path: Path, events: list[dict[str, Any]], tail: str = "") -> Path:
    path.write_text("".join(json.dumps(item) + "\n" for item in events) + tail, encoding="utf-8")
    return path


def test_writer_and_reader_agree(tmp_path: Path) -> None:
    log = DeliveryLog(tmp_path / "d.jsonl", EXECUTION)
    log.call(1)
    log.delivery(
        injection_id="k#turn1",
        turn=1,
        tool="search_docs",
        surface="description",
        delivered=True,
        reason=None,
    )
    log.delivery(
        injection_id="k#turn1",
        turn=1,
        tool="search_docs",
        surface="description",
        delivered=True,
        reason=None,
    )
    log.call(2)

    channel = read_delivery_channel(tmp_path / "d.jsonl", EXECUTION)

    assert channel is not None
    assert channel.complete
    assert channel.delivered_order("k#turn1", "search_docs") == 2
    assert channel.call_order(1) == 1
    assert channel.call_order(2) == 3
    assert len(channel.deliveries) == 1


@pytest.mark.parametrize(
    ("events", "tail"),
    [
        ([delivery(1), delivery(2)], ""),
        ([delivery(2), call(1, 1)], ""),
        ([delivery(1, execution_id="GAZUA-exec-0002")], ""),
        ([call(1, 1), call(2, 1)], ""),
        ([delivery(1)], '{"schema_version": 1, "kind": "call"'),
        ([delivery(1, delivered=False, reason=None)], ""),
        ([delivery(1, reason="not_listed")], ""),
        ([delivery(1, text="Hidden instruction")], ""),
    ],
    ids=[
        "duplicate_delivery",
        "order_backwards",
        "foreign_execution",
        "duplicate_call",
        "truncated_tail",
        "absence_without_reason",
        "delivery_with_reason",
        "unknown_field",
    ],
)
def test_missing_duplicate_or_truncated_delivery_fails_closed(
    tmp_path: Path, events: list[dict[str, Any]], tail: str
) -> None:
    channel = read_delivery_channel(write(tmp_path / "d.jsonl", events, tail), EXECUTION)

    assert channel is not None
    assert not channel.complete


def test_absent_channel_is_none(tmp_path: Path) -> None:
    assert read_delivery_channel(tmp_path / "missing.jsonl", EXECUTION) is None


def test_full_channel_stops_writing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import gazua.mcp.evidence as evidence

    monkeypatch.setattr(evidence, "MAX_DELIVERY_EVENTS", 2)
    log = DeliveryLog(tmp_path / "d.jsonl", EXECUTION)

    assert log.call(1)
    assert log.call(2)
    assert not log.call(3)
    assert log.full


def test_attribution_needs_a_complete_channel() -> None:
    from types import SimpleNamespace

    from gazua.mcp.evidence import DeliveryChannel
    from gazua.verdicts.engine import check_description_delivery
    from gazua.verdicts.signals import SignalOutcome

    config = SimpleNamespace(
        mcp=object(),
        agent_entries=SimpleNamespace(
            mcp_tool_description=SimpleNamespace(tool="search_docs", request="x")
        ),
    )
    context = SimpleNamespace(mold=SimpleNamespace(text=SimpleNamespace(en=["t"])))
    proof = SimpleNamespace(call_seq=1)
    for channel in (None, DeliveryChannel((), (), complete=False)):
        outcome = SignalOutcome()
        outcome.proofs.append(proof)  # type: ignore[arg-type]
        observed = SimpleNamespace(
            evidence=SimpleNamespace(deliveries=channel),
            record=SimpleNamespace(request_key="k"),
        )
        check_description_delivery(context, config, observed, outcome)  # type: ignore[arg-type]
        assert outcome.proofs == []
        assert outcome.reasons
