"""The per-attempt OTLP/HTTP receiver: loopback only, token protected, bounded.

It listens on ``127.0.0.1`` on an ephemeral port and serves only ``POST /v1/traces`` with an
uncompressed protobuf body. The token travels only in the ``X-Gazua-Trace-Token`` header and is
compared in constant time. A refused batch is never partially kept.
"""

from __future__ import annotations

import hmac
import ipaddress
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, ClassVar, Final

from gazua.http import TRACE_TOKEN_HEADER
from gazua.otel.evidence import TraceCollector
from gazua.otel.models import MAX_BATCH_BYTES

TRACES_PATH: Final = "/v1/traces"
PROTOBUF: Final = "application/x-protobuf"
HANDLER_TIMEOUT: Final = 5.0


class ReceiverUnavailable(OSError):
    """The listener could not start; attacks that need tool visibility are not tested."""


def _loopback(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


class _Handler(BaseHTTPRequestHandler):
    server_version = "gazua-otlp"
    sys_version = ""
    timeout = HANDLER_TIMEOUT
    receiver: ClassVar[OtlpReceiver]

    def log_message(self, format: str, *args: Any) -> None:
        return

    def answer(self, status: int, body: bytes = b"", content_type: str = "text/plain") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(body)
        self.close_connection = True

    def refuse_method(self) -> None:
        self.answer(405)

    do_GET = refuse_method
    do_PUT = refuse_method
    do_DELETE = refuse_method
    do_PATCH = refuse_method
    do_HEAD = refuse_method

    def do_POST(self) -> None:
        self.receiver.handle(self)


class OtlpReceiver:
    """One attempt's listener. Use it as a context manager; it stops on the way out."""

    def __init__(self, collector: TraceCollector) -> None:
        self.collector = collector
        self.token = secrets.token_urlsafe(32)
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def endpoint(self) -> str:
        if self._server is None:
            raise ReceiverUnavailable("otel_receiver_unavailable")
        port = self._server.server_address[1]
        return f"http://127.0.0.1:{port}{TRACES_PATH}"

    def headers(self) -> dict[str, str]:
        from gazua.http import OTLP_ENDPOINT_HEADER

        return {OTLP_ENDPOINT_HEADER: self.endpoint, TRACE_TOKEN_HEADER: self.token}

    def start(self) -> OtlpReceiver:
        handler = type("GazuaOtlpHandler", (_Handler,), {"receiver": self})
        try:
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        except OSError:
            raise ReceiverUnavailable("otel_receiver_unavailable") from None
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
        thread.daemon = True
        thread.start()
        self._server, self._thread = server, thread
        return self

    def stop(self) -> None:
        server, self._server = self._server, None
        if server is not None:
            server.shutdown()
            server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)
        self.collector.close()

    def __enter__(self) -> OtlpReceiver:
        return self.start()

    def __exit__(self, *_: object) -> None:
        self.stop()

    def handle(self, request: _Handler) -> None:
        from gazua.otel.decoder import TraceDecodeError, decode_batch, empty_response

        collector = self.collector
        if not _loopback(request.client_address[0]):
            request.answer(403)
            return
        length = request.headers.get("Content-Length", "")
        size = int(length) if length.isdigit() else None
        if size is not None and size > MAX_BATCH_BYTES:
            collector.fail("otel_payload_limit")
            request.answer(413)
            return
        try:
            body = request.rfile.read(size) if size else b""
        except OSError:
            collector.fail("otel_payload_invalid")
            return
        # The body is read before any refusal: answering mid-upload makes some systems reset
        # the connection, and the exporter would then retry instead of reading the status.
        if request.path != TRACES_PATH:
            request.answer(404)
            return
        token = request.headers.get(TRACE_TOKEN_HEADER, "")
        if not hmac.compare_digest(token.encode("utf-8"), self.token.encode("utf-8")):
            collector.fail("otel_unauthorized")
            request.answer(401)
            return
        encoding = request.headers.get("Content-Encoding", "identity").strip().lower()
        content_type = request.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if encoding != "identity" or content_type != PROTOBUF:
            collector.fail("otel_payload_invalid")
            request.answer(415, b"Only uncompressed application/x-protobuf is accepted.")
            return
        if size is None:
            collector.fail("otel_payload_invalid")
            request.answer(411)
            return
        try:
            batch = decode_batch(body, expected_run=collector.attempt_id)
        except TraceDecodeError as error:
            collector.fail(error.code)
            request.answer(413 if error.code == "otel_payload_limit" else 400)
            return
        collector.accept(batch)
        request.answer(200, empty_response(), PROTOBUF)


__all__ = ["TRACES_PATH", "OtlpReceiver", "ReceiverUnavailable"]
