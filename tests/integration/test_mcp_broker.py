import io
import json
import socket
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from mcp_support import require_mcp

from gazua.mcp import BROKER_ENV
from gazua.mcp.models import inventory_from, tool_from_definition
from gazua.mcp.proxy import read_frame, run_proxy, write_frame

EXECUTION = "GAZUA-exec-0007"


class FakeRuntime:
    """Stands in for the MCP runtime: a fixed listing and a refresh counter."""

    def __init__(self) -> None:
        self.inventory = inventory_from(
            "2025-06-18",
            [tool_from_definition({"name": "search_docs", "inputSchema": {"type": "object"}})],
        )
        self.refreshed = 0

    def refresh(self) -> Any:
        self.refreshed += 1
        return self.inventory


@pytest.fixture
def broker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    require_mcp()
    from gazua.mcp.broker import Broker

    monkeypatch.delenv(BROKER_ENV, raising=False)
    runtime = FakeRuntime()
    with Broker(runtime, tmp_path, EXECUTION) as started:  # type: ignore[arg-type]
        yield started


def context(broker: Any) -> dict[str, Any]:
    return json.loads(Path(broker.context_path).read_text(encoding="utf-8"))


def connect(broker: Any, token: str, execution: str = EXECUTION) -> socket.socket:
    found = context(broker)
    connection = socket.create_connection(("127.0.0.1", found["port"]), timeout=5)
    write_frame(connection, {"token": token, "execution_id": execution})
    return connection


def refused(connection: socket.socket) -> bool:
    try:
        read_frame(connection)
    except Exception:  # noqa: BLE001
        return True
    finally:
        connection.close()
    return False


def test_wrong_token_execution_and_method_are_rejected(broker: Any) -> None:
    found = context(broker)
    assert found["host"] == "127.0.0.1"
    assert refused(connect(broker, "0" * 64))
    assert refused(connect(broker, found["token"], "GAZUA-exec-9999"))

    good = connect(broker, found["token"])
    assert read_frame(good) == {"ok": True}
    late = connect(broker, found["token"])
    assert refused(late)

    for number, method in enumerate(
        ["sampling/createMessage", "resources/list", "prompts/list", "gazua/arm"], start=1
    ):
        write_frame(
            good,
            {"request_id": number, "message": {"jsonrpc": "2.0", "id": number, "method": method}},
        )
        reply = read_frame(good)
        assert reply["message"]["error"]["code"] == -32601
    write_frame(
        good,
        {
            "request_id": 5,
            "message": {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/list",
                "params": {"cursor": "x"},
            },
        },
    )
    assert read_frame(good)["message"]["error"]["code"] == -32602
    good.close()
    assert broker.runtime.refreshed == 0


def test_listing_carries_the_armed_text_once_per_turn(broker: Any) -> None:
    found = context(broker)
    connection = connect(broker, found["token"])
    read_frame(connection)
    listing = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}

    with broker.arm("k#turn1", "search_docs", "PAYLOAD", 1):
        for number in (1, 2):
            write_frame(connection, {"request_id": number, "message": listing})
            [tool] = read_frame(connection)["message"]["result"]["tools"]
            assert tool["description"] == "PAYLOAD"
    write_frame(connection, {"request_id": 3, "message": listing})
    [tool] = read_frame(connection)["message"]["result"]["tools"]
    connection.close()

    assert "description" not in tool
    lines = (Path(broker.directory) / "mcp-delivery.jsonl").read_text().splitlines()
    assert len(lines) == 1
    assert "PAYLOAD" not in lines[0]
    assert json.loads(lines[0])["delivered"] is True


def test_turn_without_listing_is_recorded_as_not_delivered(broker: Any) -> None:
    with broker.arm("k#turn1", "search_docs", "PAYLOAD", 1):
        pass

    [line] = (Path(broker.directory) / "mcp-delivery.jsonl").read_text().splitlines()
    event = json.loads(line)
    assert event["delivered"] is False
    assert event["reason"] == "not_listed"


def test_proxy_without_session_exits_2_before_any_upstream(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv(BROKER_ENV, raising=False)
    output, errors = io.BytesIO(), io.StringIO()

    code = run_proxy(io.BytesIO(b""), output, errors)

    assert code == 2
    assert output.getvalue() == b""
    assert "mcp_session_invalid" in errors.getvalue()
    bad = tmp_path / "context.json"
    wildcard = {"host": "0.0.0.0", "port": 1, "token": "t"}  # noqa: S104
    bad.write_text(json.dumps(wildcard), encoding="utf-8")
    monkeypatch.setenv(BROKER_ENV, str(bad))
    assert run_proxy(io.BytesIO(b""), io.BytesIO(), io.StringIO()) == 2


def test_proxy_command_refuses_outside_a_run(tmp_path: Path) -> None:
    environment = {
        key: value for key, value in __import__("os").environ.items() if key != BROKER_ENV
    }

    result = subprocess.run(
        [sys.executable, "-m", "gazua", "mcp-proxy"],
        input="",
        capture_output=True,
        text=True,
        env=environment,
        cwd=tmp_path,
        timeout=60,
        check=False,
    )

    assert result.returncode == 2
    assert result.stdout == ""


def test_proxy_answers_parse_errors_locally(broker: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(BROKER_ENV, str(broker.context_path))
    lines = (
        b"not json\n"
        + b'{"id": 1}\n'
        + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"}).encode()
        + b"\n"
    )
    output = io.BytesIO()

    assert run_proxy(io.BytesIO(lines), output, io.StringIO()) == 0

    replies = [json.loads(line) for line in output.getvalue().splitlines()]
    assert replies[0]["error"]["code"] == -32700
    assert replies[1]["error"]["code"] == -32600
    assert replies[2] == {"jsonrpc": "2.0", "id": 2, "result": {}}
