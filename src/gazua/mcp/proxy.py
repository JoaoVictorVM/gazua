"""``gazua mcp-proxy``: the stdio MCP server a test agent's client starts during a run.

It is a protocol bridge, standard library only. It reads the private broker context of the
active attempt from the file ``GAZUA_MCP_BROKER`` names, authenticates to the broker over
``127.0.0.1`` and forwards each JSON-RPC message. It never reads ``gazua.yaml``, never starts a
server, and accepts no command, policy or classification from its arguments. stdout carries
only protocol messages; short diagnostics go to stderr.
"""

from __future__ import annotations

import hmac
import json
import os
import socket
import struct
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import IO, Any, Final, cast

BROKER_ENV: Final = "GAZUA_MCP_BROKER"
BROKER_HOST: Final = "127.0.0.1"
MAX_FRAME_BYTES: Final = 1024 * 1024
MAX_CONTEXT_BYTES: Final = 4096
HANDSHAKE_SECONDS: Final = 10.0
EXIT_SESSION_INVALID: Final = 2
_HEADER = struct.Struct(">I")
_CONTEXT_KEYS = frozenset({"schema_version", "host", "port", "token", "execution_id"})


class FrameError(Exception):
    """A frame was truncated, too large or not one JSON object."""


def _receive_exactly(connection: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise FrameError("closed")
        chunks.extend(chunk)
    return bytes(chunks)


def read_frame(connection: socket.socket) -> dict[str, Any]:
    """One length-prefixed UTF-8 JSON object, at most ``MAX_FRAME_BYTES``."""
    (size,) = _HEADER.unpack(_receive_exactly(connection, _HEADER.size))
    if size > MAX_FRAME_BYTES:
        raise FrameError("too_large")
    try:
        document = json.loads(_receive_exactly(connection, size).decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise FrameError("malformed") from None
    if not isinstance(document, dict):
        raise FrameError("malformed")
    return cast("dict[str, Any]", document)


def write_frame(connection: socket.socket, document: Mapping[str, Any]) -> None:
    data = json.dumps(document, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_FRAME_BYTES:
        raise FrameError("too_large")
    connection.sendall(_HEADER.pack(len(data)) + data)


def same_secret(given: object, expected: str) -> bool:
    return isinstance(given, str) and hmac.compare_digest(given.encode(), expected.encode())


def read_context(location: str | None) -> dict[str, Any] | None:
    """The broker context of the active attempt, or None when there is no valid one."""
    if not location:
        return None
    try:
        path = Path(location)
        with path.open("rb") as handle:
            content = handle.read(MAX_CONTEXT_BYTES + 1)
        document = json.loads(content.decode("utf-8"))
    except (OSError, ValueError):
        return None
    if len(content) > MAX_CONTEXT_BYTES or not isinstance(document, dict):
        return None
    data = cast("dict[str, Any]", document)
    port = data.get("port")
    if (
        data.keys() != _CONTEXT_KEYS
        or data.get("schema_version") != 1
        or data.get("host") != BROKER_HOST
        or type(port) is not int
        or not 0 < port < 65536
        or not isinstance(data.get("token"), str)
        or not isinstance(data.get("execution_id"), str)
    ):
        return None
    return data


def _error(identifier: object, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": identifier, "error": {"code": code, "message": message}}


def _write_line(stdout: IO[bytes], message: Mapping[str, Any]) -> None:
    stdout.write(json.dumps(message, ensure_ascii=False).encode("utf-8") + b"\n")
    stdout.flush()


def _connect(context: Mapping[str, Any]) -> socket.socket | None:
    try:
        connection = socket.create_connection(
            (BROKER_HOST, context["port"]), timeout=HANDSHAKE_SECONDS
        )
    except OSError:
        return None
    try:
        write_frame(
            connection, {"token": context["token"], "execution_id": context["execution_id"]}
        )
        reply = read_frame(connection)
    except (OSError, FrameError):
        connection.close()
        return None
    if reply.get("ok") is not True:
        connection.close()
        return None
    connection.settimeout(None)
    return connection


def _skip_line(stdin: IO[bytes]) -> None:
    while True:
        rest = stdin.readline(MAX_FRAME_BYTES)
        if not rest or rest.endswith(b"\n"):
            return


def run_proxy(
    stdin: IO[bytes] | None = None,
    stdout: IO[bytes] | None = None,
    stderr: IO[str] | None = None,
) -> int:
    """Bridges stdio to the broker until the client closes stdin. 2 without a valid session."""
    reader = stdin if stdin is not None else sys.stdin.buffer
    writer = stdout if stdout is not None else sys.stdout.buffer
    errors = stderr if stderr is not None else sys.stderr
    context = read_context(os.environ.get(BROKER_ENV))
    connection = None if context is None else _connect(context)
    if connection is None:
        errors.write("gazua mcp-proxy only works inside a Gazua agent run (mcp_session_invalid).\n")
        return EXIT_SESSION_INVALID
    number = 0
    with connection:
        while True:
            line = reader.readline(MAX_FRAME_BYTES + 1)
            if not line:
                return 0
            if len(line) > MAX_FRAME_BYTES:
                _skip_line(reader)
                _write_line(writer, _error(None, -32600, "Message too large"))
                continue
            if not line.strip():
                continue
            try:
                message: object = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                _write_line(writer, _error(None, -32700, "Parse error"))
                continue
            if (
                not isinstance(message, dict)
                or cast("dict[str, Any]", message).get("jsonrpc") != "2.0"
            ):
                identifier = (
                    cast("dict[str, Any]", message).get("id") if isinstance(message, dict) else None
                )
                _write_line(writer, _error(identifier, -32600, "Invalid Request"))
                continue
            number += 1
            try:
                write_frame(connection, {"request_id": number, "message": message})
                reply = read_frame(connection)
            except (OSError, FrameError):
                errors.write("gazua mcp-proxy lost the broker (mcp_transport_lost).\n")
                return 1
            if reply.get("request_id") != number:
                errors.write("gazua mcp-proxy received a reply out of order.\n")
                return 1
            answer = reply.get("message")
            if isinstance(answer, dict):
                _write_line(writer, cast("dict[str, Any]", answer))
