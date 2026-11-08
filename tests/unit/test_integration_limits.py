import asyncio
import contextlib
import json
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import gazua
from gazua.integration.errors import GazuaBlockedError
from gazua.integration.limits import admitted_calls, reset_admissions
from gazua.integration.session import SESSION_ENV

Policy = Callable[..., dict[str, Any]]
EXECUTION = "GAZUA-exec-0001"


def start_execution(
    folder: Path, monkeypatch: pytest.MonkeyPatch, tools: dict[str, Any], ceiling: int = 50
) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    document = {
        "schema_version": 2,
        "run_id": "GAZUA-run-1",
        "mode": "agent",
        "call_log": "calls.jsonl",
        "actor": None,
        "as_user": None,
        "tools": tools,
        "injections": [],
        "execution_id": EXECUTION,
        "max_tool_calls": ceiling,
        "events_path": "events.jsonl",
        "receiver": None,
        "usage_reporting": False,
    }
    path = folder / "session.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setenv(SESSION_ENV, str(path))
    return folder


def events(folder: Path) -> list[dict[str, Any]]:
    text = (folder / "events.jsonl").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines()]


def calls(folder: Path) -> list[dict[str, Any]]:
    path = folder / "calls.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


@pytest.mark.parametrize("dry_run", [False, True], ids=["real", "dry-run"])
def test_call_fifty_latches_ceiling_and_call_fifty_one_never_executes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, policy: Policy, dry_run: bool
) -> None:
    folder = start_execution(
        tmp_path / "run", monkeypatch, {"touch": policy(dry_run=dry_run), "atouch": policy()}
    )
    effects: list[int] = []
    effects_lock = threading.Lock()

    def touch(number: int) -> str:
        with effects_lock:
            effects.append(number)
        return "ok"

    async def atouch(number: int) -> str:
        return "ok"

    touch_proxy, atouch_proxy = gazua.wrap([touch, atouch])
    refused: list[int] = []
    refused_lock = threading.Lock()

    def worker(start: int) -> None:
        for number in range(start, start + 20):
            try:
                if number % 7 == 0:
                    asyncio.run(atouch_proxy(number))
                else:
                    touch_proxy(number)
            # The target catches the refusal and keeps trying, as a runaway loop would.
            except GazuaBlockedError as error:
                with refused_lock:
                    refused.append(number if error.reason == "tool_call_ceiling" else -1)

    threads = [threading.Thread(target=worker, args=(index * 20,)) for index in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert admitted_calls(EXECUTION) == 50
    assert len(refused) == 30
    assert -1 not in refused
    assert len(calls(folder)) == 50
    if dry_run:
        assert effects == []
    else:
        touched = [record for record in calls(folder) if record["tool"] == "touch"]
        assert len(effects) == len(touched)
    kinds = [event["kind"] for event in events(folder)]
    assert kinds.count("tool_call_admitted") == 50
    assert kinds.count("tool_call_ceiling") == 1
    assert kinds.index("tool_call_ceiling") == len(kinds) - 1
    assert events(folder)[-1]["payload"] == {"count": 50}

    with pytest.raises(GazuaBlockedError):
        touch_proxy(999)
    assert admitted_calls(EXECUTION) == 50
    assert 999 not in effects


def test_hanging_tool_consumes_slot_before_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, policy: Policy
) -> None:
    folder = start_execution(tmp_path / "run", monkeypatch, {"hang": policy(dry_run=False)}, 2)
    entered = threading.Event()
    release = threading.Event()

    def hang() -> str:
        entered.set()
        release.wait(10)
        return "done"

    (proxy,) = gazua.wrap([hang])
    first = threading.Thread(target=proxy)
    first.start()
    assert entered.wait(5)

    # The slot is taken although the call log has no record of the unfinished call.
    assert admitted_calls(EXECUTION) == 1
    assert calls(folder) == []
    assert [event["payload"]["count"] for event in events(folder)] == [1]

    entered.clear()
    second = threading.Thread(target=proxy)
    second.start()
    assert entered.wait(5)
    with pytest.raises(GazuaBlockedError):
        proxy()
    release.set()
    first.join()
    second.join()
    assert admitted_calls(EXECUTION) == 2
    assert [event["kind"] for event in events(folder)][-1] == "tool_call_ceiling"


def test_version_one_session_keeps_previous_behavior(
    start_session: Callable[..., Path], policy: Policy
) -> None:
    log = start_session(tools={"touch": policy(dry_run=False)})

    def touch() -> str:
        return "ok"

    (proxy,) = gazua.wrap([touch])
    for _ in range(60):
        proxy()

    assert len(log.read_text(encoding="utf-8").splitlines()) == 60
    assert not (log.parent / "events.jsonl").exists()


@settings(
    max_examples=25, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(ceiling=st.integers(1, 8), attempts=st.integers(0, 20), threads=st.integers(1, 4))
def test_no_call_passes_the_ceiling_for_any_interleaving(
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
    ceiling: int,
    attempts: int,
    threads: int,
) -> None:
    from gazua.integration.channel import clear_channels
    from gazua.integration.registry import registry

    reset_admissions()
    clear_channels()
    registry.clear()
    folder = start_execution(
        tmp_path_factory.mktemp("run"),
        monkeypatch,
        {"touch": {"dry_run": False, "actor_arg": None, "has_dry_run_return": False,
                   "dry_run_return": None}},
        ceiling,
    )  # fmt: skip
    ran: list[int] = []

    def touch() -> str:
        ran.append(1)
        return "ok"

    (proxy,) = gazua.wrap([touch])

    def worker() -> None:
        for _ in range(attempts):
            with contextlib.suppress(GazuaBlockedError):
                proxy()

    pool = [threading.Thread(target=worker) for _ in range(threads)]
    for thread in pool:
        thread.start()
    for thread in pool:
        thread.join()

    assert len(ran) == min(ceiling, attempts * threads)
    assert admitted_calls(EXECUTION) == len(ran)
    assert len(calls(folder)) == len(ran)
