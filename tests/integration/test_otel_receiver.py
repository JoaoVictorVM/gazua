"""The per-attempt OTLP receiver: loopback bind, token, paths, limits and closing."""

from __future__ import annotations

import gzip
import http.client
import socket
import time
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from http_support import (
    FORBIDDEN_TOOL,
    AgentServer,
    HttpProject,
    SpanSpec,
    build_batch,
    export_spans,
    require_otel,
)

CRLF = chr(13) + chr(10)
RUN = "GAZUA-run-20260101000000-abc123:GAZUA-exec-0001"


@pytest.fixture
def receiver() -> object:
    require_otel()
    from gazua.otel.evidence import TraceCollector
    from gazua.otel.receiver import OtlpReceiver

    collector = TraceCollector("GAZUA-exec-0001", RUN, time.time_ns() - 1_000_000_000)
    with OtlpReceiver(collector) as started:
        yield started


def _raw(endpoint: str, method: str, path: str, body: bytes, headers: dict[str, str]) -> int:
    parts = urlsplit(endpoint)
    connection = http.client.HTTPConnection(parts.hostname or "", parts.port, timeout=5)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def _announced_size(endpoint: str, token: str, size: int) -> int:
    """Sends only the headers of a batch that big: the receiver refuses before reading it."""
    parts = urlsplit(endpoint)
    with socket.create_connection((parts.hostname or "", parts.port or 0), timeout=5) as raw:
        lines = [
            "POST /v1/traces HTTP/1.1",
            "Host: 127.0.0.1",
            "Content-Type: application/x-protobuf",
            f"X-Gazua-Trace-Token: {token}",
            f"Content-Length: {size}",
            "",
            "",
        ]
        raw.sendall(CRLF.join(lines).encode("ascii"))
        status_line = raw.makefile("rb").readline().decode("ascii")
    return int(status_line.split()[1])


def test_receiver_requires_token_and_loopback(receiver: object) -> None:
    from gazua.otel.receiver import OtlpReceiver

    assert isinstance(receiver, OtlpReceiver)
    endpoint = receiver.endpoint
    assert endpoint.startswith("http://127.0.0.1:")
    assert receiver._server is not None  # pyright: ignore[reportPrivateUsage]
    assert receiver._server.server_address[0] == "127.0.0.1"  # pyright: ignore[reportPrivateUsage]
    spans = [SpanSpec(FORBIDDEN_TOOL)]
    body = build_batch(RUN, spans)
    protobuf = {"Content-Type": "application/x-protobuf"}

    assert export_spans(endpoint, None, RUN, spans) == 401
    assert export_spans(endpoint, "wrong-token", RUN, spans) == 401
    assert _raw(endpoint, "POST", "/v1/metrics", body, {**protobuf}) == 404
    assert _raw(endpoint, "GET", "/v1/traces", b"", {}) == 405
    token = {"X-Gazua-Trace-Token": receiver.token}
    assert _raw(endpoint, "POST", "/v1/traces?token=x", body, {**protobuf, **token}) == 404
    gzipped = {**protobuf, **token, "Content-Encoding": "gzip"}
    assert _raw(endpoint, "POST", "/v1/traces", gzip.compress(body), gzipped) == 415
    as_json = {"Content-Type": "application/json", **token}
    assert _raw(endpoint, "POST", "/v1/traces", b"{}", as_json) == 415
    assert _raw(endpoint, "POST", "/v1/traces", b"\xff\x00garbage", {**protobuf, **token}) == 400
    assert _announced_size(endpoint, receiver.token, 4 * 1024 * 1024 + 1) == 413

    evidence = receiver.collector.evidence()
    # Every refused batch left the channel incomplete, and none of it was kept.
    assert evidence.accepted == 0
    assert not evidence.complete


def test_valid_batch_is_kept_once_and_closing_stops_the_listener(receiver: object) -> None:
    from gazua.otel.receiver import OtlpReceiver

    assert isinstance(receiver, OtlpReceiver)
    endpoint = receiver.endpoint
    span_id = b"\x01" * 8
    spans = [SpanSpec(FORBIDDEN_TOOL, span_id=span_id)]
    body = build_batch(RUN, spans)

    assert export_spans(endpoint, receiver.token, RUN, spans, body=body) == 200
    assert export_spans(endpoint, receiver.token, RUN, spans, body=body) == 200
    receiver.stop()

    evidence = receiver.collector.evidence()
    assert evidence.complete
    assert evidence.accepted == 1
    assert evidence.duplicates == 1
    assert evidence.tool_spans[0].tool == FORBIDDEN_TOOL
    with pytest.raises(ConnectionError):
        export_spans(endpoint, receiver.token, RUN, spans, body=body)


def test_ephemeral_headers_enable_correlated_export(tmp_path: Path) -> None:
    with AgentServer("vulnerable") as target:
        project = HttpProject(tmp_path, target.url())

        result = project.run_agent(["permission-05"])

        assert result.verdicts.results[0].state == "finding"
        tokens = {item.headers["X-Gazua-Trace-Token"] for item in target.requests}
        endpoints = {item.headers["X-Gazua-OTLP-Endpoint"] for item in target.requests}
        # Each attempt gets its own listener and token.
        assert len(tokens) == len(target.requests)
        assert len(endpoints) == len(target.requests)
        stored = b"".join(
            path.read_bytes() for path in (tmp_path / ".gazua").rglob("*") if path.is_file()
        ).decode("utf-8", errors="replace")
        for value in tokens | endpoints:
            assert value not in stored
        assert "private prompt that must never persist" not in stored
        assert "private-service-name" not in stored
