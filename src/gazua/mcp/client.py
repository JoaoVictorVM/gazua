"""Client of one MCP server over stdio, run on a private event loop thread.

Gazua starts the server from an argument vector, without a shell, in the folder the
configuration names and with only the minimal system environment the SDK deems safe to inherit:
no ``GAZUA_*`` variable, token or private path reaches it. Each message line is limited before
it is parsed. Sampling, elicitation and roots are never announced, so the server cannot ask
Gazua for a model, a file or a URL. The server's stderr is discarded, never printed.
"""

from __future__ import annotations

import asyncio
import contextlib
import shutil
import subprocess
import threading
from collections.abc import AsyncGenerator, Callable, Coroutine, Mapping, Sequence
from concurrent.futures import Future
from datetime import timedelta
from pathlib import Path
from typing import Any, TypeVar, cast

import anyio
import anyio.lowlevel
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from mcp import ClientSession, types
from mcp.client.stdio import get_default_environment
from mcp.shared.exceptions import McpError as ProtocolError
from mcp.shared.message import SessionMessage
from mcp.shared.session import RequestResponder

from gazua.mcp import gazua_version
from gazua.mcp.models import (
    ACCEPTED_PROTOCOL_VERSIONS,
    GRACEFUL_SECONDS,
    MAX_INVENTORY_BYTES,
    MAX_MESSAGE_BYTES,
    MAX_PAGES,
    MAX_TOOLS,
    STARTUP_SECONDS,
    McpError,
    McpInventory,
    McpLaunch,
    McpTool,
    inventory_from,
    tool_from_definition,
)

_Result = TypeVar("_Result")
_Incoming = SessionMessage | Exception
_Message = RequestResponder[types.ServerRequest, types.ClientResult] | types.ServerNotification


class McpCallFailed(Exception):
    """The server answered a call with a protocol error, or with a result that is not valid."""


def server_environment() -> dict[str, str]:
    """The minimal system variables a launcher needs; nothing that carries Gazua's state."""
    return {
        key: value
        for key, value in get_default_environment().items()
        if not key.upper().startswith("GAZUA")
    }


def resolve_executable(launch: McpLaunch, environment: Mapping[str, str]) -> str:
    """The executable's full path, resolved before anything starts.

    A name with a path separator is relative to the server folder; a bare name is searched in
    the server's ``PATH``. Raises ``McpError`` when nothing executable is found.
    """
    command = launch.command
    if "/" in command or "\\" in command:
        path = Path(command)
        candidate = path if path.is_absolute() else launch.cwd / path
        if candidate.is_file():
            return str(candidate)
        raise McpError("mcp_start_failed")
    found = shutil.which(command, path=environment.get("PATH"))
    if found is None:
        raise McpError("mcp_start_failed")
    return found


def _failure_code(failure: BaseException, default: str) -> str:
    if isinstance(failure, McpError):
        return failure.code
    if isinstance(failure, BaseExceptionGroup):
        group = cast("BaseExceptionGroup[BaseException]", failure)
        for inner in group.exceptions:
            code = _failure_code(inner, "")
            if code:
                return code
    return default


class _Violation:
    def __init__(self) -> None:
        self.code: str | None = None

    def mark(self, code: str) -> None:
        if self.code is None:
            self.code = code


@contextlib.asynccontextmanager
async def _stdio(
    argv: Sequence[str], cwd: Path, environment: Mapping[str, str], violation: _Violation
) -> AsyncGenerator[tuple[MemoryObjectReceiveStream[_Incoming], MemoryObjectSendStream[Any]]]:
    incoming_send, incoming = anyio.create_memory_object_stream[_Incoming](0)
    outgoing, outgoing_receive = anyio.create_memory_object_stream[SessionMessage](0)
    process = await anyio.open_process(
        list(argv), cwd=cwd, env=dict(environment), stderr=subprocess.DEVNULL
    )

    async def read() -> None:
        stdout = process.stdout
        if stdout is None:
            return
        buffer = b""
        async with incoming_send:
            async for chunk in stdout:
                buffer += chunk
                *lines, buffer = buffer.split(b"\n")
                for line in lines:
                    if len(line) > MAX_MESSAGE_BYTES:
                        violation.mark("mcp_inventory_limit")
                        return
                    if not line.strip():
                        continue
                    try:
                        message = types.JSONRPCMessage.model_validate_json(line)
                    except ValueError as error:
                        violation.mark("mcp_inventory_invalid")
                        await incoming_send.send(error)
                        continue
                    await incoming_send.send(SessionMessage(message))
                if len(buffer) > MAX_MESSAGE_BYTES:
                    violation.mark("mcp_inventory_limit")
                    return

    async def write() -> None:
        stdin = process.stdin
        if stdin is None:
            return
        async with outgoing_receive:
            async for item in outgoing_receive:
                data = item.message.model_dump_json(by_alias=True, exclude_none=True)
                await stdin.send(data.encode("utf-8") + b"\n")

    async with anyio.create_task_group() as group:
        group.start_soon(read)
        group.start_soon(write)
        try:
            yield incoming, outgoing
        finally:
            with anyio.CancelScope(shield=True):
                if process.stdin is not None:
                    with contextlib.suppress(Exception):
                        await process.stdin.aclose()
                with anyio.move_on_after(GRACEFUL_SECONDS):
                    await process.wait()
                if process.returncode is None:
                    with contextlib.suppress(Exception):
                        process.kill()
                    with anyio.move_on_after(GRACEFUL_SECONDS):
                        await process.wait()
            group.cancel_scope.cancel()
            await incoming.aclose()
            await outgoing.aclose()


class McpClient:
    """One MCP session: initialize, paginated ``tools/list`` and ``tools/call``.

    Every public method blocks the calling thread and raises ``McpError`` with a public code.
    A call whose answer is lost is never sent again.
    """

    def __init__(self, launch: McpLaunch, *, timeout: float = STARTUP_SECONDS) -> None:
        self.launch = launch
        self.timeout = timeout
        self.protocol_version: str | None = None
        self.list_changed = threading.Event()
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, name="gazua-mcp", daemon=True)
        self._ready = threading.Event()
        self._stop = asyncio.Event()
        self._violation = _Violation()
        self._failure: str | None = None
        self._session: ClientSession | None = None
        self._serving: Future[None] | None = None
        self._lost = False
        self._closed = False

    def __enter__(self) -> McpClient:
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def start(self) -> None:
        environment = server_environment()
        if not self.launch.cwd.is_dir():
            raise McpError("mcp_start_failed")
        executable = resolve_executable(self.launch, environment)
        self._thread.start()
        argv = [executable, *self.launch.args]
        self._serving = asyncio.run_coroutine_threadsafe(self._serve(argv, environment), self._loop)
        if not self._ready.wait(self.timeout):
            self.close()
            raise McpError("mcp_start_timeout")
        if self._failure is not None or self._session is None:
            code = self._failure or "mcp_start_failed"
            self.close()
            raise McpError(code)

    async def _on_message(self, message: _Message | Exception) -> None:
        if isinstance(message, types.ServerNotification) and isinstance(
            message.root, types.ToolListChangedNotification
        ):
            self.list_changed.set()
        elif isinstance(message, Exception):
            self._violation.mark("mcp_inventory_invalid")
        await anyio.lowlevel.checkpoint()

    async def _serve(self, argv: list[str], environment: dict[str, str]) -> None:
        try:
            async with (
                _stdio(argv, self.launch.cwd, environment, self._violation) as (read, write),
                ClientSession(
                    read,
                    write,
                    read_timeout_seconds=timedelta(seconds=self.timeout),
                    message_handler=self._on_message,
                    client_info=types.Implementation(name="gazua", version=gazua_version()),
                ) as session,
            ):
                result = await session.initialize()
                if (
                    result.protocolVersion not in ACCEPTED_PROTOCOL_VERSIONS
                    or result.capabilities.tools is None
                ):
                    raise McpError("mcp_protocol_unsupported")
                self.protocol_version = result.protocolVersion
                self._session = session
                self._ready.set()
                await self._stop.wait()
        # The transport, the SDK and the server can fail in any way; only a code is kept.
        except BaseException as failure:  # noqa: BLE001
            started = self._ready.is_set()
            default = "mcp_transport_lost" if started else "mcp_start_failed"
            if not self._stop.is_set():
                self._failure = _failure_code(failure, default)
        finally:
            self._session = None
            self._lost = True
            self._ready.set()

    def _run(
        self,
        factory: Callable[[ClientSession], Coroutine[Any, Any, _Result]],
        timeout: float,
    ) -> _Result:
        session = self._session
        if session is None or self._lost:
            raise McpError(self._failure or self._violation.code or "mcp_transport_lost")
        future = asyncio.run_coroutine_threadsafe(factory(session), self._loop)
        try:
            return future.result(timeout)
        except TimeoutError:
            future.cancel()
            self._lost = True
            raise McpError("mcp_transport_lost") from None

    def list_inventory(self) -> McpInventory:
        """A complete listing, every page, or ``McpError``; never a partial inventory."""
        self.list_changed.clear()
        try:
            tools = self._run(_list_all, self.timeout)
        except McpError as failure:
            raise McpError(self._violation.code or failure.code) from None
        # An invalid page fails in the SDK's own validation; the transport may say why first.
        except Exception:  # noqa: BLE001
            raise McpError(self._violation.code or "mcp_inventory_invalid") from None
        if self._violation.code is not None:
            raise McpError(self._violation.code)
        return inventory_from(self.protocol_version or "", tools)

    def call_tool(
        self, name: str, arguments: Mapping[str, Any], timeout: float | None = None
    ) -> dict[str, Any]:
        """The result as MCP JSON. A protocol error or an invalid result is ``McpCallFailed``."""

        async def call(session: ClientSession) -> types.CallToolResult:
            return await session.call_tool(name, dict(arguments))

        try:
            result = self._run(call, timeout or self.timeout)
        except ProtocolError:
            raise McpCallFailed("mcp_call_failed") from None
        except RuntimeError:
            raise McpCallFailed("mcp_result_invalid") from None
        return result.model_dump(mode="json", by_alias=True, exclude_none=True)

    @property
    def usable(self) -> bool:
        return self._session is not None and not self._lost

    def close(self) -> None:
        """Ends the session, waits briefly for the server and stops the loop. Idempotent."""
        if self._closed:
            return
        self._closed = True
        if self._thread.is_alive():
            self._loop.call_soon_threadsafe(self._stop.set)
            if self._serving is not None:
                with contextlib.suppress(Exception):
                    self._serving.result(GRACEFUL_SECONDS * 3)
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join(GRACEFUL_SECONDS)
        if not self._thread.is_alive():
            self._loop.close()


async def _list_all(session: ClientSession) -> list[McpTool]:
    cursors: set[str] = set()
    tools: list[McpTool] = []
    names: set[str] = set()
    cursor: str | None = None
    total = 0
    for _ in range(MAX_PAGES):
        params = None if cursor is None else types.PaginatedRequestParams(cursor=cursor)
        page = await session.list_tools(params=params)
        total += len(page.model_dump_json(by_alias=True, exclude_none=True).encode("utf-8"))
        if total > MAX_INVENTORY_BYTES:
            raise McpError("mcp_inventory_limit")
        for item in page.tools:
            tool = tool_from_definition(item.model_dump(mode="json", by_alias=True))
            if tool.name in names:
                raise McpError("mcp_inventory_invalid")
            names.add(tool.name)
            tools.append(tool)
        if len(tools) > MAX_TOOLS:
            raise McpError("mcp_inventory_limit")
        cursor = page.nextCursor
        if cursor is None:
            return tools
        if cursor in cursors:
            raise McpError("mcp_inventory_invalid")
        cursors.add(cursor)
    raise McpError("mcp_inventory_limit")
