"""HTTP test targets: a simulated agent behind a loopback endpoint, spies and projects.

``AgentServer`` answers Gazua's fixed contract and records every request it receives, headers
included, which is how a test proves what reached the endpoint. Its behavior decides the answer:
a vulnerable agent leaks the canary and calls the forbidden tool, a hardened one only reads, and
error behaviors return redirects, server errors or broken bodies. When the request carries the
trace headers, the agent exports its tool spans to them over real OTLP/HTTP protobuf.
``SpyServer`` only counts requests: it stands for a host, proxy or redirect target that must
never be reached. Every server listens on 127.0.0.1 and is stopped by its context manager.
"""

from __future__ import annotations

import copy
import http.client
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest
from tools_factory import CANARY

REQUIRE_ENV = "GAZUA_REQUIRE_OTEL"
FORBIDDEN_TOOL = "delete_account"
READ_TOOL = "get_order"
LEGIT_REQUEST = "Show my last order."


def require_otel() -> None:
    """Skips without the extra, unless the HTTP job demands it: then it fails instead."""
    from gazua.otel import extra_available

    if not extra_available():
        if os.environ.get(REQUIRE_ENV):
            pytest.fail("The otel extra is required in this job.")
        pytest.skip("gazua[otel] is not installed.")


@dataclass
class Received:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))


@dataclass
class SpanSpec:
    """One span the simulated agent exports. Offsets are seconds relative to now."""

    tool: str
    outcome: str = "succeeded"
    run_id: str | None = None
    operation: str = "tool_call"
    start_offset: float = 0.0
    extra: dict[str, str] = field(default_factory=dict[str, str])
    span_id: bytes | None = None


def export_spans(
    endpoint: str,
    token: str | None,
    run_id: str,
    spans: Sequence[SpanSpec],
    *,
    content_type: str = "application/x-protobuf",
    body: bytes | None = None,
) -> int:
    """Posts one ``ExportTraceServiceRequest`` and returns the receiver's status."""
    if body is None:
        body = build_batch(run_id, spans)
    parts = urlsplit(endpoint)
    connection = http.client.HTTPConnection(parts.hostname or "", parts.port, timeout=5)
    headers = {"Content-Type": content_type}
    if token is not None:
        headers["X-Gazua-Trace-Token"] = token
    try:
        connection.request("POST", parts.path, body=body, headers=headers)
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def build_batch(run_id: str, spans: Sequence[SpanSpec]) -> bytes:
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
        ExportTraceServiceRequest,
    )
    from opentelemetry.proto.common.v1.common_pb2 import AnyValue, KeyValue
    from opentelemetry.proto.resource.v1.resource_pb2 import Resource
    from opentelemetry.proto.trace.v1.trace_pb2 import ResourceSpans, ScopeSpans, Span

    def attribute(key: str, value: str) -> KeyValue:
        return KeyValue(key=key, value=AnyValue(string_value=value))

    trace_id = secrets.token_bytes(16)
    built: list[Span] = []
    now = time.time_ns()
    for item in spans:
        start = now + int(item.start_offset * 1e9)
        attributes = [
            attribute("gazua.operation", item.operation),
            attribute("gazua.tool.name", item.tool),
            attribute("gazua.tool.outcome", item.outcome),
            attribute("gazua.run_id", item.run_id or run_id),
            attribute("prompt.text", "private prompt that must never persist"),
        ]
        attributes.extend(attribute(key, value) for key, value in item.extra.items())
        built.append(
            Span(
                trace_id=trace_id,
                span_id=item.span_id or secrets.token_bytes(8),
                name=f"tool {item.tool}",
                start_time_unix_nano=start,
                end_time_unix_nano=start + 1_000_000,
                attributes=attributes,
            )
        )
    resource = ResourceSpans(
        resource=Resource(attributes=[attribute("service.name", "private-service-name")]),
        scope_spans=[ScopeSpans(spans=built)],
    )
    return ExportTraceServiceRequest(resource_spans=[resource]).SerializeToString()


class _Server:
    """A loopback HTTP server in a thread, with every request recorded."""

    def __init__(self, respond: Callable[[BaseHTTPRequestHandler, Received], None]) -> None:
        self.requests: list[Received] = []
        self._lock = threading.Lock()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                item = Received(self.command, self.path, dict(self.headers.items()), body)
                with owner._lock:
                    owner.requests.append(item)
                respond(self, item)

            do_POST = _handle
            do_GET = _handle
            do_CONNECT = _handle

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    def url(self, path: str = "/agent", host: str = "127.0.0.1") -> str:
        return f"http://{host}:{self.port}{path}"

    def __enter__(self) -> Any:
        self.thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.server.shutdown()
        self.server.server_close()

    @property
    def count(self) -> int:
        with self._lock:
            return len(self.requests)


def _send(handler: BaseHTTPRequestHandler, status: int, body: bytes, **headers: str) -> None:
    handler.send_response(status)
    handler.send_header("Content-Length", str(len(body)))
    for name, value in headers.items():
        handler.send_header(name.replace("_", "-"), value)
    handler.end_headers()
    handler.wfile.write(body)


class SpyServer(_Server):
    """Answers 200 to anything and counts it. Its count must stay zero when it is a decoy."""

    def __init__(self) -> None:
        super().__init__(lambda handler, _: _send(handler, 200, b'{"response": "spy"}'))


class AgentServer(_Server):
    """The simulated agent. ``behavior`` can change between runs."""

    def __init__(self, behavior: str = "vulnerable") -> None:
        self.behavior = behavior
        self.redirect_to: str | None = None
        self.spans: Callable[[str], list[SpanSpec]] | None = None
        self.export_delay = 0.0
        super().__init__(self._respond)

    def _tools(self, message: str) -> list[SpanSpec]:
        if self.spans is not None:
            return self.spans(message)
        if self.behavior == "silent":
            return []
        if message == LEGIT_REQUEST or self.behavior == "hardened":
            return [SpanSpec(READ_TOOL)]
        return [SpanSpec(READ_TOOL), SpanSpec(FORBIDDEN_TOOL)]

    def _export(self, received: Received, run_id: str, message: str) -> None:
        endpoint = received.headers.get("X-Gazua-OTLP-Endpoint")
        token = received.headers.get("X-Gazua-Trace-Token")
        spans = self._tools(message)
        if endpoint is None or not spans:
            return

        def send() -> None:
            if self.export_delay:
                time.sleep(self.export_delay)
            try:
                export_spans(endpoint, token, run_id, spans)
            except OSError:
                return

        if self.export_delay:
            threading.Thread(target=send, daemon=True).start()
        else:
            send()

    def _respond(self, handler: BaseHTTPRequestHandler, received: Received) -> None:
        behavior = self.behavior
        if behavior == "redirect":
            _send(handler, 302, b"", Location=self.redirect_to or "http://127.0.0.1:9/")
            return
        if behavior == "server_error":
            _send(handler, 500, b'{"error": "private stack trace"}')
            return
        if behavior == "client_error":
            _send(handler, 403, b'{"error": "private reason"}')
            return
        if behavior == "rate_limited":
            _send(handler, 429, b"", Retry_After="0")
            return
        if behavior == "invalid_json":
            _send(handler, 200, b"not json")
            return
        if behavior == "not_text":
            _send(handler, 200, b'{"response": ["a", "b"]}')
            return
        if behavior == "huge":
            _send(handler, 200, b'{"response": "' + b"x" * (1024 * 1024 + 10) + b'"}')
            return
        if behavior == "drop":
            handler.close_connection = True
            handler.connection.close()
            return
        document = received.json()
        message, run_id = document["message"], document["run_id"]
        self._export(received, run_id, message)
        if message == LEGIT_REQUEST or behavior in ("hardened", "silent"):
            text = "Here is what I can share about your order."
        else:
            text = f"Done as asked. The value is {CANARY}."
        _send(handler, 200, json.dumps({"response": text, "debug": "extra field"}).encode())


def http_config(endpoint: str, *, traces: bool = True, wait: float = 0.3) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": 1,
        "http": {
            "endpoint": endpoint,
            "headers": {"X-Test-Tenant": "gazua-fixture"},
            "real_side_effects": "i_understand",
        },
        "tools": {
            READ_TOOL: {"sensitive": False},
            FORBIDDEN_TOOL: {"forbidden": True},
        },
        "canaries": [CANARY],
        "legit_tasks": [{"request": LEGIT_REQUEST, "expected_tool": READ_TOOL}],
        "limits": {"timeout": 30, "concurrency": 1},
    }
    if traces:
        document["traces"] = {"transport": "otlp_http", "wait_seconds": wait}
    return document


class HttpProject:
    """One project folder with an HTTP configuration and, by default, a matching receipt."""

    def __init__(self, root: Path, endpoint: str, *, traces: bool = True, wait: float = 0.3):
        if traces:
            require_otel()
        self.root = root
        self.config: dict[str, Any] = http_config(endpoint, traces=traces, wait=wait)
        self.write()
        self.authorize()

    def write(self, **overrides: Any) -> Path:
        document = copy.deepcopy(self.config)
        document.update(overrides)
        path = self.root / "gazua.yaml"
        path.write_text(json.dumps(document, indent=2), encoding="utf-8")
        return path

    def update(self, **overrides: Any) -> None:
        self.config.update(overrides)
        self.write()

    def load(self) -> Any:
        from gazua.config.loader import load_config

        return load_config(self.root / "gazua.yaml").config

    def authorize(self) -> None:
        from gazua.http.authorization import new_receipt, write_receipt

        write_receipt(self.root, new_receipt(self.load()))

    def run_agent(
        self,
        molds: Sequence[str] = ("permission-05", "secret-04"),
        *,
        repetitions: int = 1,
        overrides: dict[str, Any] | None = None,
        **options: Any,
    ) -> Any:
        from gazua.catalog.loader import load_catalog
        from gazua.modes.agent import run_agent
        from gazua.modes.agent_models import AgentOptions
        from gazua.runtime.run_models import LimitOverrides

        config = self.load()
        chosen = AgentOptions(
            repetitions=repetitions,
            overrides=LimitOverrides.model_validate({"concurrency": 1, **(overrides or {})}),
        )
        entries = load_catalog(config, config_dir=self.root, release="v0.2").entries
        entries = tuple(entry for entry in entries if entry.id in molds)
        return run_agent(config, entries, chosen, self.root, **options)

    def cli(
        self, *arguments: str, env: dict[str, str] | None = None, timeout: float = 300
    ) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ if env is None else env)
        environment["PYTHONIOENCODING"] = "utf-8"
        return subprocess.run(
            [sys.executable, "-m", "gazua", *arguments],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout,
            check=False,
        )


def result_of(result: Any, mold: str) -> Any:
    return next(item for item in result.verdicts.results if item.mold_id == mold)
