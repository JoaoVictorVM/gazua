"""Broker of one agent attempt: the only path from ``gazua mcp-proxy`` to the MCP server.

It listens on ``127.0.0.1`` on an ephemeral port and accepts one proxy, authenticated with a
random 256-bit token and the attempt's execution id. It answers ``initialize``, ``ping``,
``tools/list`` and ``tools/call``; every other method is refused, and no message from the
proxy can arm a turn, change a policy or start a process. Calls go through the registered
Gazua tools, so dry-run, the actor, the ceiling and the call log apply as in Python targets.

While a turn is armed, the description of the declared tool carries that turn's text. The
first listing that holds it records a delivery after the answer was written to the proxy.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import socket
import threading
from collections.abc import Callable, Generator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, cast

from gazua.integration.errors import GazuaBlockedError
from gazua.mcp import BROKER_ENV, gazua_version
from gazua.mcp.evidence import DeliveryLog, McpToolError, to_call_result
from gazua.mcp.executor import McpArgumentsInvalid, McpCallError, McpRunBlocked, McpRuntime
from gazua.mcp.models import ACCEPTED_PROTOCOL_VERSIONS, BROKER_FILE, DELIVERY_FILE
from gazua.mcp.proxy import (
    BROKER_HOST,
    HANDSHAKE_SECONDS,
    FrameError,
    read_frame,
    same_secret,
    write_frame,
)

SERVER_NAME: Final = "gazua-mcp-proxy"
BLOCKED_TEXT: Final = "Gazua did not run this tool call."
_LIST_METHODS: Final = frozenset({"tools/list"})


@dataclass(frozen=True, slots=True)
class ArmedTurn:
    injection_id: str
    tool: str
    text: str
    turn: int


def _response(identifier: object, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": identifier, "result": result}


def _error(identifier: object, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": identifier, "error": {"code": code, "message": message}}


def _blocked_result() -> dict[str, Any]:
    return {"content": [{"type": "text", "text": BLOCKED_TEXT}], "isError": True}


class Broker:
    """Serves one proxy for one attempt. Use it as a context manager inside the worker."""

    def __init__(self, runtime: McpRuntime, directory: Path, execution_id: str) -> None:
        self.runtime = runtime
        self.directory = directory
        self.execution_id = execution_id
        self.deliveries = DeliveryLog(directory / DELIVERY_FILE, execution_id)
        self.context_path = directory / BROKER_FILE
        self._token = secrets.token_hex(32)
        self._lock = threading.Lock()
        self._armed: ArmedTurn | None = None
        self._listener: socket.socket | None = None
        self._client: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._recorded_calls: set[int] = set()
        self._closing = False
        self.evidence_failed = False

    # Lifecycle

    def __enter__(self) -> Broker:
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def start(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind((BROKER_HOST, 0))
        listener.listen(4)
        self._listener = listener
        port = cast("tuple[str, int]", listener.getsockname())[1]
        context = {
            "schema_version": 1,
            "host": BROKER_HOST,
            "port": port,
            "token": self._token,
            "execution_id": self.execution_id,
        }
        descriptor = os.open(self.context_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(context))
        os.environ[BROKER_ENV] = str(self.context_path)
        self._thread = threading.Thread(target=self._accept, name="gazua-mcp-broker", daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._closing = True
        os.environ.pop(BROKER_ENV, None)
        for item in (self._client, self._listener):
            if item is not None:
                with contextlib.suppress(OSError):
                    item.close()
        if self._thread is not None:
            self._thread.join(2)
        self.context_path.unlink(missing_ok=True)

    def _accept(self) -> None:
        listener = self._listener
        if listener is None:
            return
        while not self._closing:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            if self._client is not None or not self._authenticate(connection):
                with contextlib.suppress(OSError):
                    connection.close()
                continue
            self._client = connection
            self._serve(connection)
            return

    def _authenticate(self, connection: socket.socket) -> bool:
        try:
            connection.settimeout(HANDSHAKE_SECONDS)
            hello = read_frame(connection)
            valid = same_secret(hello.get("token"), self._token) and same_secret(
                hello.get("execution_id"), self.execution_id
            )
            if not valid:
                return False
            write_frame(connection, {"ok": True})
            connection.settimeout(None)
        except (OSError, FrameError):
            return False
        return True

    def _serve(self, connection: socket.socket) -> None:
        while not self._closing:
            try:
                frame = read_frame(connection)
            except (OSError, FrameError):
                return
            number = frame.get("request_id")
            message = frame.get("message")
            if type(number) is not int or number < 1 or not isinstance(message, dict):
                return
            answer, after = self.handle(cast("dict[str, Any]", message))
            try:
                write_frame(connection, {"request_id": number, "message": answer})
            except (OSError, FrameError):
                return
            if after is not None:
                after()

    # Turns

    @contextlib.contextmanager
    def arm(self, injection_id: str, tool: str, text: str, turn: int) -> Generator[None]:
        """Only this turn's text can reach the declared tool's description inside the block."""
        with self._lock:
            self._armed = ArmedTurn(injection_id, tool, text, turn)
        try:
            yield
        finally:
            with self._lock:
                self._armed = None
            if injection_id not in self.deliveries.delivered:
                self._record(injection_id, turn, tool, delivered=False, reason="not_listed")

    def _record(
        self, injection_id: str, turn: int, tool: str, *, delivered: bool, reason: str | None
    ) -> None:
        written = self.deliveries.delivery(
            injection_id=injection_id,
            turn=turn,
            tool=tool,
            surface="description",
            delivered=delivered,
            reason=reason,
        )
        if self.deliveries.full and not written:
            self.evidence_failed = True

    # Protocol

    def handle(self, message: dict[str, Any]) -> tuple[dict[str, Any] | None, Any]:
        """The answer to one client message, and what to record once it was written."""
        identifier = message.get("id")
        method = message.get("method")
        if not isinstance(method, str):
            return None, None
        if identifier is None:
            return None, None
        params = message.get("params")
        if params is not None and not isinstance(params, dict):
            return _error(identifier, -32602, "Invalid params"), None
        values = cast("dict[str, Any]", params or {})
        if method == "initialize":
            requested = values.get("protocolVersion")
            chosen = (
                requested
                if requested in ACCEPTED_PROTOCOL_VERSIONS
                else ACCEPTED_PROTOCOL_VERSIONS[0]
            )
            return _response(
                identifier,
                {
                    "protocolVersion": chosen,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": SERVER_NAME, "version": gazua_version()},
                },
            ), None
        if method == "ping":
            return _response(identifier, {}), None
        if method in _LIST_METHODS:
            return self._list(identifier, values)
        if method == "tools/call":
            return self._call(identifier, values), None
        return _error(identifier, -32601, "Method not found"), None

    def _list(self, identifier: object, values: dict[str, Any]) -> tuple[dict[str, Any], Any]:
        if values.get("cursor") is not None:
            return _error(identifier, -32602, "Invalid cursor"), None
        try:
            inventory = self.runtime.refresh()
        except McpRunBlocked:
            return _error(identifier, -32603, "Tool list unavailable"), None
        with self._lock:
            armed = self._armed
        tools: list[dict[str, Any]] = []
        carried = False
        for tool in inventory.tools:
            definition = tool.definition()
            if armed is not None and tool.name == armed.tool:
                base = tool.description or ""
                definition["description"] = f"{base}\n{armed.text}" if base else armed.text
                carried = True
            tools.append(definition)
        after: Callable[[], None] | None = None
        if armed is not None and carried:

            def record() -> None:
                self._record(
                    armed.injection_id, armed.turn, armed.tool, delivered=True, reason=None
                )

            after = record

        return _response(identifier, {"tools": tools}), after

    def _call(self, identifier: object, values: dict[str, Any]) -> dict[str, Any]:
        from gazua.integration.registry import registry

        name = values.get("name")
        arguments = values.get("arguments", {})
        if not isinstance(name, str) or not isinstance(arguments, dict):
            return _error(identifier, -32602, "Invalid params")
        entries = registry.snapshot().get(name)
        if not entries or entries[0].proxy is None:
            return _error(identifier, -32602, f"Unknown tool: {name}")
        proxy = entries[0].proxy
        try:
            value = proxy(**cast("dict[str, Any]", arguments))
        except McpArgumentsInvalid:
            result: dict[str, Any] | None = None
            answer = _error(identifier, -32602, "Invalid arguments")
        except McpToolError as failure:
            result, answer = failure.result, None
        except McpRunBlocked:
            result, answer = None, _error(identifier, -32603, "Tool unavailable")
        except McpCallError:
            result, answer = None, _error(identifier, -32603, "Tool call failed")
        except TypeError:
            result, answer = None, _error(identifier, -32602, "Invalid arguments")
        except GazuaBlockedError:
            result, answer = _blocked_result(), None
        # The forwarder and the wrapper record every failure; the agent only sees an error.
        except Exception:  # noqa: BLE001
            result, answer = _blocked_result(), None
        else:
            result, answer = to_call_result(value), None
        self._correlate()
        if answer is not None:
            return answer
        return _response(identifier, result or _blocked_result())

    def _correlate(self) -> None:
        from gazua.integration.calllog import call_log_for
        from gazua.integration.session import Session, session_state

        state = session_state()
        if not isinstance(state, Session):
            return
        seq = call_log_for(state.call_log).last_seq()
        if seq < 1 or seq in self._recorded_calls:
            return
        self._recorded_calls.add(seq)
        if not self.deliveries.call(seq):
            self.evidence_failed = True
