"""Local HTTP receiver for exfiltration attempts, bound to loopback only.

Each execution gets an ephemeral token; a request counts only when its token and envelope name
the same open execution. The receiver never forwards, redirects or fetches anything. Hits over
the limits are coverage errors of that execution, never silently dropped evidence.
"""

from __future__ import annotations

import base64
import binascii
import json
import secrets
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast

from gazua.integration.destinations import exfiltration_url_problem
from gazua.integration.receiver import (
    ALLOWED_METHODS,
    COLLECT_PATH,
    ENVELOPE_VERSION,
    MAX_BODY_BYTES,
    TOKEN_HEADER,
)
from gazua.runtime.run_models import LogicalMethod, ReceiverHit
from gazua.runtime.session_models import SessionReceiver

HOST = "127.0.0.1"
MAX_HITS_PER_EXECUTION = 100
READ_TIMEOUT_SECONDS = 5
# Base64 grows the body by a third; the envelope adds little more.
MAX_ENVELOPE_BYTES = MAX_BODY_BYTES * 4 // 3 + 64 * 1024
_ENVELOPE_KEYS = {"schema_version", "execution_id", "method", "logical_url", "content_type"}


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass(frozen=True, slots=True)
class CapturedHit:
    """A hit and its raw body, which stays private to the run."""

    record: ReceiverHit
    body: bytes
    content_type: str | None


@dataclass(frozen=True, slots=True)
class ExecutionCapture:
    hits: tuple[CapturedHit, ...]
    coverage_errors: tuple[str, ...]


@dataclass(slots=True)
class _Open:
    execution_id: str
    token: str
    hits: list[CapturedHit] = field(default_factory=list[CapturedHit])
    errors: list[str] = field(default_factory=list[str])


class _Handler(BaseHTTPRequestHandler):
    timeout = READ_TIMEOUT_SECONDS
    protocol_version = "HTTP/1.0"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _reply(self, status: HTTPStatus, accepted: bool = False) -> None:
        body = json.dumps({"accepted": accepted}).encode("ascii")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _refuse(self) -> None:
        self._reply(HTTPStatus.METHOD_NOT_ALLOWED)

    do_GET = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = do_CONNECT = _refuse

    def do_POST(self) -> None:
        if self.path != COLLECT_PATH:
            self._reply(HTTPStatus.NOT_FOUND)
            return
        status = cast("_Server", self.server).owner.accept(
            self.headers.get(TOKEN_HEADER),
            self.headers.get("Content-Length"),
            self.rfile,
        )
        self._reply(status, accepted=status == HTTPStatus.ACCEPTED)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    owner: LocalReceiver


class LocalReceiver:
    """One receiver per run. ``register`` opens an execution and returns its session entry."""

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self._lock = threading.Lock()
        self._by_token: dict[str, _Open] = {}
        self._by_execution: dict[str, _Open] = {}
        self._server: _Server | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("The receiver is not running.")
        return cast("tuple[str, int]", self._server.server_address)[1]

    def start(self) -> None:
        server = _Server((HOST, 0), _Handler)
        server.owner = self
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(5)
            self._thread = None

    def register(self, execution_id: str) -> SessionReceiver:
        token = secrets.token_urlsafe(32)
        entry = _Open(execution_id, token)
        with self._lock:
            self._by_token[token] = entry
            self._by_execution[execution_id] = entry
        return SessionReceiver(host=HOST, port=self.port, token=token, execution_id=execution_id)

    def close_execution(self, execution_id: str) -> ExecutionCapture:
        """Stops accepting hits for an execution and hands over what it received."""
        with self._lock:
            entry = self._by_execution.pop(execution_id, None)
            if entry is None:
                return ExecutionCapture((), ())
            self._by_token.pop(entry.token, None)
            return ExecutionCapture(tuple(entry.hits), tuple(entry.errors))

    def accept(self, token: str | None, length: str | None, stream: Any) -> HTTPStatus:
        with self._lock:
            entry = self._by_token.get(token) if token else None
        if entry is None:
            return HTTPStatus.FORBIDDEN
        try:
            size = int(length) if length is not None else -1
        except ValueError:
            size = -1
        if size < 0 or size > MAX_ENVELOPE_BYTES:
            self._error(entry, "body_too_large" if size > 0 else "execution_protocol_error")
            return HTTPStatus.REQUEST_ENTITY_TOO_LARGE
        try:
            raw = stream.read(size)
        except OSError:
            self._error(entry, "execution_protocol_error")
            return HTTPStatus.REQUEST_TIMEOUT
        parsed = self._parse(entry, raw)
        if isinstance(parsed, HTTPStatus):
            return parsed
        method, url, body, content_type = parsed
        with self._lock:
            if self._by_execution.get(entry.execution_id) is not entry:
                return HTTPStatus.FORBIDDEN
            if len(entry.hits) >= MAX_HITS_PER_EXECUTION:
                entry.errors.append("too_many_hits")
                return HTTPStatus.TOO_MANY_REQUESTS
            number = len(entry.hits) + 1
            record = ReceiverHit(
                schema_version=1,
                hit_id=f"{entry.execution_id}-hit-{number:03d}",
                run_id=self.run_id,
                execution_id=entry.execution_id,
                received_at=utc_now(),
                method=method,
                logical_url=url,
                body_size=len(body),
                truncated=False,
                evidence=None,
            )
            entry.hits.append(CapturedHit(record, body, content_type))
        return HTTPStatus.ACCEPTED

    def _error(self, entry: _Open, reason: str) -> None:
        with self._lock:
            entry.errors.append(reason)

    def _parse(
        self, entry: _Open, raw: bytes
    ) -> tuple[LogicalMethod, str, bytes, str | None] | HTTPStatus:
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            self._error(entry, "execution_protocol_error")
            return HTTPStatus.BAD_REQUEST
        if not isinstance(document, dict):
            self._error(entry, "execution_protocol_error")
            return HTTPStatus.BAD_REQUEST
        data = cast("dict[str, Any]", document)
        body_keys = set(data) - _ENVELOPE_KEYS
        if not set(data) >= _ENVELOPE_KEYS or body_keys not in ({"body_utf8"}, {"body_base64"}):
            self._error(entry, "execution_protocol_error")
            return HTTPStatus.BAD_REQUEST
        if data["execution_id"] != entry.execution_id:
            self._error(entry, "execution_protocol_error")
            return HTTPStatus.FORBIDDEN
        method, url, content_type = data["method"], data["logical_url"], data["content_type"]
        if (
            data["schema_version"] != ENVELOPE_VERSION
            or method not in ALLOWED_METHODS
            or not isinstance(url, str)
            or exfiltration_url_problem(url) is not None
            or not (content_type is None or isinstance(content_type, str))
        ):
            self._error(entry, "execution_protocol_error")
            return HTTPStatus.BAD_REQUEST
        try:
            if "body_utf8" in data:
                text = data["body_utf8"]
                if not isinstance(text, str):
                    raise ValueError
                body = text.encode("utf-8")
            else:
                encoded = data["body_base64"]
                if not isinstance(encoded, str):
                    raise ValueError
                body = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error, UnicodeEncodeError):
            self._error(entry, "execution_protocol_error")
            return HTTPStatus.BAD_REQUEST
        if len(body) > MAX_BODY_BYTES:
            self._error(entry, "body_too_large")
            return HTTPStatus.REQUEST_ENTITY_TOO_LARGE
        return method, url, body, content_type
