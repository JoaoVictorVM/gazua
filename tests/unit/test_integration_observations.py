import json
import threading
from pathlib import Path
from typing import Any

import pytest

import gazua
from gazua.integration import observations
from gazua.runtime.call_log import read_call_log
from gazua.runtime.observations import RETURNS_FILE, read_return_channel

EXECUTION = "GAZUA-exec-0007"


class Opaque:
    def __init__(self) -> None:
        self.touched = False

    def __repr__(self) -> str:
        self.touched = True
        return "opaque"


def v2(policy: Any, **tools: Any) -> dict[str, Any]:
    return {
        "schema_version": 2,
        "execution_id": EXECUTION,
        "max_tool_calls": 500,
        "events_path": "events.jsonl",
        "receiver": None,
        "usage_reporting": False,
        "tools": {name: policy(**values) for name, values in tools.items()},
    }


def sidecar_lines(folder: Path) -> list[dict[str, Any]]:
    path = folder / RETURNS_FILE
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def channel(log: Path) -> Any:
    reading = read_call_log(log)
    return read_return_channel(log.parent / RETURNS_FILE, EXECUTION, reading.records)


def test_private_returns_preserve_sequences_and_limits(
    start_session: Any, policy: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    ran: list[str] = []
    opaque = Opaque()

    def get_order(order_id: str) -> dict[str, Any]:
        return {"order_id": order_id, "user_id": "victim-1", "items": [1, 2.5, None, True]}

    def refund(amount: int) -> str:
        ran.append("refund")
        return "real refund"

    def describe() -> Opaque:
        return opaque

    def huge() -> str:
        return "x" * (observations.MAX_OBSERVATION_BYTES + 1)

    def note() -> str:
        return "note"

    log = start_session(
        **v2(
            policy,
            get_order={"dry_run": False},
            refund={"has_dry_run_return": True, "dry_run_return": {"status": "queued"}},
            describe={"dry_run": False},
            huge={"dry_run": False},
            note={"dry_run": False},
        ),
        injections=[{"id": "inj-1", "tool": "note", "text": "INJECTED", "max_deliveries": 1}],
    )
    tools = gazua.wrap(
        {"get_order": get_order, "refund": refund, "describe": describe, "huge": huge, "note": note}
    )

    threads = [
        threading.Thread(target=tools["get_order"], args=(f"order-{index}",)) for index in range(16)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert tools["refund"](5) == {"status": "queued"}
    assert tools["describe"]() is opaque
    assert len(tools["huge"]()) == observations.MAX_OBSERVATION_BYTES + 1
    assert tools["note"]() == "note\nINJECTED"

    assert ran == []
    assert not opaque.touched
    lines = sidecar_lines(log.parent)
    records = read_call_log(log).records
    # The log and the sidecar are written under separate locks, so concurrent calls can land
    # in a different order in each file; the reader correlates them by sequence.
    assert sorted(line["call_seq"] for line in lines) == [record.seq for record in records]
    by_seq = {line["call_seq"]: line for line in lines}
    for record in records[:16]:
        line = by_seq[record.seq]
        assert line["original"]["order_id"] == record.arguments["order_id"]
        assert line["original"] == line["delivered"]
    refund_line = by_seq[records[16].seq]
    assert refund_line["original"] == {"status": "queued"}
    assert by_seq[records[17].seq]["unavailable_reason"] == "not_serializable"
    assert by_seq[records[18].seq]["unavailable_reason"] == "too_large"
    note_line = by_seq[records[19].seq]
    assert (note_line["original"], note_line["delivered"]) == ("note", "note\nINJECTED")
    assert all(line["execution_id"] == EXECUTION for line in lines)

    reading = channel(log)
    assert reading.valid
    assert reading.missing == (records[17].seq, records[18].seq)
    assert reading.value(records[0].seq) is not None
    assert reading.value(records[17].seq) is None

    with (log.parent / RETURNS_FILE).open("a", encoding="utf-8") as handle:
        handle.write('{"schema_version": 1, "kind": "tool_ret')
    truncated = channel(log)
    assert truncated.valid
    assert truncated.truncated_tail


def test_sidecar_refuses_lines_that_do_not_match_a_returned_call(
    start_session: Any, policy: Any
) -> None:
    log = start_session(**v2(policy, ok={"dry_run": False}))

    def ok() -> int:
        return 1

    gazua.wrap({"ok": ok})["ok"]()
    reading = read_call_log(log)
    path = log.parent / RETURNS_FILE
    good = path.read_text(encoding="utf-8")
    assert read_return_channel(path, EXECUTION, reading.records).valid

    for forged in (
        good.replace('"call_seq":1', '"call_seq":9'),
        good.replace(EXECUTION, "GAZUA-exec-0099"),
        good + good,
        good + "{not json}\n",
        good.replace('"original":1', '"original":1,"verdict":"finding"'),
    ):
        path.write_text(forged, encoding="utf-8")
        result = read_return_channel(path, EXECUTION, reading.records)
        assert not result.valid
        assert result.value(1) is None
        assert result.missing == (1,)

    path.unlink()
    absent = read_return_channel(path, EXECUTION, reading.records)
    assert absent.valid
    assert absent.missing == (1,)
    assert absent.reason == "return_observation_unavailable"


def test_execution_limit_and_v1_session_keep_tool_behavior(
    start_session: Any, policy: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(observations, "MAX_EXECUTION_BYTES", 400)

    def echo(text: str) -> str:
        return text

    log = start_session(**v2(policy, echo={"dry_run": False}))
    echo_tool = gazua.wrap({"echo": echo})["echo"]
    values = [echo_tool("y" * 60) for _ in range(6)]
    assert values == ["y" * 60] * 6
    reasons = [line.get("unavailable_reason") for line in sidecar_lines(log.parent)]
    assert reasons[0] is None
    assert reasons[-1] == "execution_limit"
    assert (log.parent / RETURNS_FILE).stat().st_size < 1000

    observations.clear_sidecars()
    (log.parent / RETURNS_FILE).unlink()
    v1_log = start_session(tools={"echo": policy(dry_run=False)})
    assert echo_tool("plain") == "plain"
    assert read_call_log(v1_log).records[-1].outcome == "returned"
    assert not (v1_log.parent / RETURNS_FILE).exists()


def test_unwritable_sidecar_never_changes_the_return(
    start_session: Any, policy: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.name == RETURNS_FILE:
            raise OSError("disk full")
        return original_open(self, *args, **kwargs)

    original_open = Path.open
    monkeypatch.setattr(Path, "open", failing_open)
    log = start_session(**v2(policy, echo={"dry_run": False}))

    def echo(text: str) -> str:
        return text

    assert gazua.wrap({"echo": echo})["echo"]("kept") == "kept"
    monkeypatch.setattr(Path, "open", original_open)
    reading = channel(log)
    assert reading.valid
    assert reading.missing == (1,)
