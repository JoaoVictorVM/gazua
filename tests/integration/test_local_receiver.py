import base64
import http.client
import json
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from gazua.runtime.receiver import MAX_HITS_PER_EXECUTION, LocalReceiver

Runner = Callable[..., Any]

TARGET = r"""
import json, sys
seen = {"lookups": [], "connects": []}

def audit(event, args):
    if event == "socket.getaddrinfo":
        seen["lookups"].append(str(args[0]))
    if event == "socket.connect":
        seen["connects"].append(list(args[1])[:2])

sys.addaudithook(audit)
import gazua
gazua.send_to_receiver(
    "https://receiver.gazua.test/collect", body="GAZUA-CANARY-01 leaked by the agent"
)
print(json.dumps(seen))
"""


@pytest.fixture
def receiver() -> Iterator[LocalReceiver]:
    server = LocalReceiver("GAZUA-run-1")
    server.start()
    yield server
    server.stop()


def post(
    port: int, body: bytes, token: str | None, path: str = "/collect", method: str = "POST"
) -> tuple[int, bytes, dict[str, str]]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["X-Gazua-Token"] = token
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    data = response.read()
    connection.close()
    return response.status, data, dict(response.getheaders())


def envelope(execution_id: str, body: str = "GAZUA-CANARY-01", **extra: Any) -> bytes:
    document: dict[str, Any] = {
        "schema_version": 1,
        "execution_id": execution_id,
        "method": "POST",
        "logical_url": "https://receiver.gazua.test/collect",
        "content_type": None,
        "body_utf8": body,
    }
    document.update(extra)
    return json.dumps(document).encode()


def test_reserved_request_reaches_receiver_without_external_connection(
    receiver: LocalReceiver,
    tmp_path: Path,
    run_isolated: Runner,
    clean_environment: Callable[[], dict[str, str]],
) -> None:
    entry = receiver.register("GAZUA-exec-0001")
    session = {
        "schema_version": 2,
        "run_id": "GAZUA-run-1",
        "mode": "agent",
        "call_log": "calls.jsonl",
        "actor": None,
        "as_user": None,
        "tools": {},
        "injections": [],
        "execution_id": "GAZUA-exec-0001",
        "max_tool_calls": 50,
        "events_path": "events.jsonl",
        "receiver": entry.model_dump(),
        "usage_reporting": False,
    }
    (tmp_path / "session.json").write_text(json.dumps(session), encoding="utf-8")
    script = tmp_path / "target.py"
    script.write_text(TARGET, encoding="utf-8")
    environment = {
        **clean_environment(),
        "GAZUA_SESSION": str(tmp_path / "session.json"),
        "HTTPS_PROXY": "http://proxy.invalid:3128",
    }

    result = run_isolated([sys.executable, script], cwd=tmp_path, env=environment)

    assert result.returncode == 0, result.stderr
    seen = json.loads(result.stdout)
    assert seen["lookups"] in ([], ["127.0.0.1"])
    assert seen["connects"] == [["127.0.0.1", entry.port]]
    capture = receiver.close_execution("GAZUA-exec-0001")
    (hit,) = capture.hits
    assert b"GAZUA-CANARY-01" in hit.body
    assert hit.record.logical_url == "https://receiver.gazua.test/collect"
    assert hit.record.execution_id == "GAZUA-exec-0001"
    assert capture.coverage_errors == ()


def test_receiver_rejects_wrong_token_large_body_redirect_and_cross_execution_hit(
    receiver: LocalReceiver,
) -> None:
    first = receiver.register("GAZUA-exec-0001")
    second = receiver.register("GAZUA-exec-0002")
    port = first.port

    assert post(port, envelope("GAZUA-exec-0001"), "wrong-token")[0] == 403
    assert post(port, envelope("GAZUA-exec-0001"), None)[0] == 403
    # The token of one execution cannot record a hit in another one.
    assert post(port, envelope("GAZUA-exec-0002"), first.token)[0] == 403
    assert post(port, envelope("GAZUA-exec-0001"), first.token, path="/redirect")[0] == 404
    for method in ("GET", "PUT", "DELETE"):
        assert post(port, b"", first.token, method=method)[0] == 405
    foreign = envelope("GAZUA-exec-0001", logical_url="https://example.com/collect")
    assert post(port, foreign, first.token)[0] == 400
    oversized = json.loads(envelope("GAZUA-exec-0001"))
    del oversized["body_utf8"]
    oversized["body_base64"] = base64.b64encode(b"x" * (1024 * 1024 + 10)).decode()
    assert post(port, json.dumps(oversized).encode(), first.token)[0] == 413

    status, data, headers = post(port, envelope("GAZUA-exec-0002"), second.token)
    assert status == 202
    assert json.loads(data) == {"accepted": True}
    assert "Location" not in headers

    first_capture = receiver.close_execution("GAZUA-exec-0001")
    second_capture = receiver.close_execution("GAZUA-exec-0002")
    assert first_capture.hits == ()
    assert "execution_protocol_error" in first_capture.coverage_errors
    assert "body_too_large" in first_capture.coverage_errors
    assert [hit.record.execution_id for hit in second_capture.hits] == ["GAZUA-exec-0002"]

    # A closed execution accepts nothing more.
    assert post(port, envelope("GAZUA-exec-0002"), second.token)[0] == 403


def test_hits_over_the_limit_are_coverage_errors(receiver: LocalReceiver) -> None:
    entry = receiver.register("GAZUA-exec-0001")
    statuses = [
        post(entry.port, envelope("GAZUA-exec-0001", body=f"hit {index}"), entry.token)[0]
        for index in range(MAX_HITS_PER_EXECUTION + 2)
    ]

    assert statuses.count(202) == MAX_HITS_PER_EXECUTION
    assert statuses[-2:] == [429, 429]
    capture = receiver.close_execution("GAZUA-exec-0001")
    assert len(capture.hits) == MAX_HITS_PER_EXECUTION
    assert capture.coverage_errors == ("too_many_hits", "too_many_hits")
    assert len({hit.record.hit_id for hit in capture.hits}) == MAX_HITS_PER_EXECUTION
