import json
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import gazua
from gazua.integration.receiver import GazuaReceiverError
from gazua.integration.session import SESSION_ENV
from gazua.runtime.receiver import LocalReceiver

EXECUTION = "GAZUA-exec-0001"


@pytest.fixture
def receiver() -> Iterator[LocalReceiver]:
    server = LocalReceiver("GAZUA-run-1")
    server.start()
    yield server
    server.stop()


class NetworkSpy:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.lookups: list[str] = []
        self.connections: list[tuple[str, int]] = []
        real_lookup = socket.getaddrinfo
        real_connect = socket.create_connection

        def lookup(host: Any, *args: Any, **kwargs: Any) -> Any:
            self.lookups.append(str(host))
            return real_lookup(host, *args, **kwargs)

        def connect(address: tuple[str, int], *args: Any, **kwargs: Any) -> Any:
            self.connections.append(address)
            return real_connect(address, *args, **kwargs)

        monkeypatch.setattr(socket, "getaddrinfo", lookup)
        monkeypatch.setattr(socket, "create_connection", connect)


def start_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, receiver: dict[str, Any] | None
) -> None:
    document = {
        "schema_version": 2,
        "run_id": "GAZUA-run-1",
        "mode": "agent",
        "call_log": "calls.jsonl",
        "actor": None,
        "as_user": None,
        "tools": {},
        "injections": [],
        "execution_id": EXECUTION,
        "max_tool_calls": 50,
        "events_path": "events.jsonl",
        "receiver": receiver,
        "usage_reporting": False,
    }
    path = tmp_path / "session.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setenv(SESSION_ENV, str(path))


def test_reserved_https_is_a_logical_destination_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, receiver: LocalReceiver
) -> None:
    entry = receiver.register(EXECUTION)
    start_execution(tmp_path, monkeypatch, entry.model_dump())
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://proxy.invalid:3128")
    spy = NetworkSpy(monkeypatch)

    gazua.send_to_receiver(
        "https://receiver.gazua.test/collect",
        body="GAZUA-CANARY-01",
        headers={"Authorization": "Bearer GAZUA-secret", "Content-Type": "text/plain"},
    )
    gazua.send_to_receiver("http://drop.gazua.test/x", method="PUT", body=b"\xff\x00")

    assert all(host == "127.0.0.1" for host, _ in spy.connections)
    assert spy.connections == [("127.0.0.1", entry.port)] * 2
    assert not any("gazua.test" in host or "proxy" in host for host in spy.lookups)
    capture = receiver.close_execution(EXECUTION)
    assert capture.coverage_errors == ()
    first, second = capture.hits
    assert first.record.logical_url == "https://receiver.gazua.test/collect"
    assert first.body == b"GAZUA-CANARY-01"
    assert first.content_type == "text/plain"
    assert second.record.method == "PUT"
    assert second.body == b"\xff\x00"
    assert "Bearer" not in json.dumps([hit.record.model_dump() for hit in capture.hits])


@pytest.mark.parametrize(
    ("url", "with_session", "with_receiver", "reason"),
    [
        ("https://receiver.gazua.test/collect", False, False, "no_session"),
        ("https://receiver.gazua.test/collect", True, False, "receiver_unavailable"),
        ("https://example.com/collect", True, True, "invalid_exfiltration_domain"),
        ("https://receiver.gazua.test.example.com/", True, True, "invalid_exfiltration_domain"),
        ("https://receiver.gazua.test:8443/x", True, True, "invalid_exfiltration_domain"),
        ("https://127.0.0.1/collect", True, True, "invalid_exfiltration_domain"),
        ("ftp://receiver.gazua.test/x", True, True, "invalid_exfiltration_domain"),
    ],
)
def test_missing_session_foreign_host_and_invalid_endpoint_never_connect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    receiver: LocalReceiver,
    url: str,
    with_session: bool,
    with_receiver: bool,
    reason: str,
) -> None:
    monkeypatch.delenv(SESSION_ENV, raising=False)
    entry = receiver.register(EXECUTION)
    if with_session:
        start_execution(tmp_path, monkeypatch, entry.model_dump() if with_receiver else None)
    spy = NetworkSpy(monkeypatch)

    with pytest.raises(GazuaReceiverError) as refused:
        gazua.send_to_receiver(url, body="GAZUA-CANARY-01")

    assert refused.value.reason == reason
    assert spy.connections == []
    assert spy.lookups == []
    assert receiver.close_execution(EXECUTION).hits == ()

    # Positive control: the same spy sees the connection of a valid request.
    start_execution(tmp_path, monkeypatch, receiver.register(EXECUTION).model_dump())
    gazua.send_to_receiver("https://receiver.gazua.test/collect", body="ok")
    assert spy.connections


def test_invalid_session_and_methods_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "session.json"
    path.write_text("{broken", encoding="utf-8")
    monkeypatch.setenv(SESSION_ENV, str(path))

    with pytest.raises(GazuaReceiverError) as invalid:
        gazua.send_to_receiver("https://receiver.gazua.test/collect")
    assert invalid.value.reason == "invalid_session"
    with pytest.raises(GazuaReceiverError) as method:
        gazua.send_to_receiver("https://receiver.gazua.test/collect", method="CONNECT")
    assert method.value.reason == "invalid_method"
    with pytest.raises(GazuaReceiverError) as large:
        gazua.send_to_receiver("https://receiver.gazua.test/c", body=b"x" * (1024 * 1024 + 1))
    assert large.value.reason == "body_too_large"
