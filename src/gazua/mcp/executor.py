"""The MCP session of one supervised worker: client, approved snapshot and forwarders.

Each listed tool is registered as a regular Gazua tool whose original function forwards the
call to the server. The wrapper in front of it keeps every existing contract: the call ceiling,
dry-run, the imposed actor, the call log, injections and the private return channel. A dry-run
never reaches the forwarder, so a tool that is not ``safe: true`` never reaches the server.

Before every real call the forwarder lists the tools again and compares the definition with
the snapshot approved at planning. A changed or removed tool is refused locally; a tool that
appeared after planning stays in dry-run, even when a declaration with its name says it is safe.
"""

from __future__ import annotations

import contextlib
import json
import threading
from collections.abc import Generator, Iterable, Mapping
from pathlib import Path
from typing import Any, cast

from gazua.config.models import GazuaConfig
from gazua.integration.errors import GazuaBlockedError
from gazua.mcp import EXTRA_MISSING_CODE, extra_available
from gazua.mcp.discovery import (
    EXTRA_PARAMETER,
    forwarder_signature,
    launch_for,
    omitted,
    reconcile,
)
from gazua.mcp.evidence import McpToolError, normalize_result
from gazua.mcp.models import (
    STARTUP_SECONDS,
    McpError,
    McpInventory,
    McpTool,
    changed_tools,
    new_tools,
)
from gazua.mcp.policy import arguments_valid, schema_problem


class McpRunBlocked(GazuaBlockedError):
    """The MCP session cannot be trusted for this attempt; ``reason`` is the public code.

    ``changed`` names the approved tools whose definition changed, so the supervisor can stop
    the attempts that depend on them.
    """

    def __init__(self, reason: str, changed: Iterable[str] = ()) -> None:
        super().__init__(reason)
        self.changed = tuple(sorted(changed))


class McpArgumentsInvalid(ValueError):
    """The arguments break the tool's input schema; the call was not forwarded."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class McpCallError(RuntimeError):
    """The server answered the call with a protocol error or an invalid result."""


def _client_type() -> Any:
    from gazua.mcp.client import McpClient

    return McpClient


class McpRuntime:
    """One attempt's MCP session. Calls are serialized; nothing is retried."""

    def __init__(
        self,
        config: GazuaConfig,
        project_root: Path,
        *,
        approved: Mapping[str, str] | None,
        dependent: Iterable[str] = (),
        timeout: float = STARTUP_SECONDS,
    ) -> None:
        if config.mcp is None:
            raise ValueError("The configuration declares no MCP server.")
        self.config = config
        self.launch = launch_for(config.mcp, project_root)
        self.timeout = min(STARTUP_SECONDS, timeout)
        self.approved: dict[str, str] | None = None if approved is None else dict(approved)
        self.dependent = frozenset(dependent)
        self.inventory: McpInventory | None = None
        self.changed: set[str] = set()
        self.new: set[str] = set()
        self.failure: str | None = None
        self._lock = threading.RLock()
        self._client: Any = None

    # Session

    def start(self) -> McpInventory:
        """Starts the server, lists every tool and checks the approved snapshot."""
        if not extra_available():
            raise McpRunBlocked(EXTRA_MISSING_CODE)
        client = _client_type()(self.launch, timeout=self.timeout)
        try:
            client.start()
            self._client = client
            inventory = client.list_inventory()
        except McpError as failure:
            client.close()
            self._client = None
            raise McpRunBlocked(failure.code) from None
        if self.approved is None:
            self.approved = inventory.digests()
        self._accept(inventory)
        if self.failure is not None:
            client.close()
            self._client = None
            raise McpRunBlocked(self.failure, self.changed)
        return inventory

    def _accept(self, inventory: McpInventory) -> None:
        approved = self.approved or {}
        changed = set(changed_tools(approved, inventory))
        self.changed |= changed
        self.new |= set(new_tools(approved, inventory))
        self.inventory = inventory
        if changed & self.dependent:
            self.failure = "mcp_tool_changed"

    def refresh(self) -> McpInventory:
        """Lists again. A failed listing leaves the inventory unknown and blocks every call."""
        try:
            inventory = self._require_client().list_inventory()
        except McpError as failure:
            self.failure = self.failure or failure.code
            raise McpRunBlocked(self.failure) from None
        self._accept(inventory)
        return inventory

    def _require_client(self) -> Any:
        if self._client is None:
            raise McpRunBlocked(self.failure or "mcp_transport_lost")
        return self._client

    def close(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            client.close()

    def raise_if_invalid(self) -> None:
        if self.failure is not None:
            raise McpRunBlocked(self.failure, self.changed)

    @property
    def released(self) -> frozenset[str]:
        """Approved names the session may forward; new tools never are."""
        return frozenset(self.approved or {})

    # Calls

    def forward(self, name: str, arguments: Mapping[str, Any]) -> Any:
        """Sends one released call. Raises instead of returning when anything is in doubt."""
        with self._lock:
            if self.failure is not None:
                raise McpRunBlocked(self.failure)
            if name not in self.released:
                raise McpRunBlocked("blocked_real_call")
            inventory = self.refresh()
            tool = inventory.get(name)
            if tool is None or name in self.changed:
                self.failure = "mcp_tool_changed"
                raise McpRunBlocked(self.failure, self.changed)
            if schema_problem(tool.input_schema) is not None:
                raise McpArgumentsInvalid("mcp_schema_unsupported")
            if not arguments_valid(tool.input_schema, arguments):
                raise McpArgumentsInvalid("mcp_arguments_invalid")
            from gazua.mcp.client import McpCallFailed

            try:
                result = self._require_client().call_tool(name, arguments)
            except McpCallFailed as failure:
                raise McpCallError(str(failure)) from None
            except McpError as failure:
                self.failure = failure.code
                raise McpRunBlocked(failure.code) from None
            if result.get("isError") is True:
                raise McpToolError(result)
            return normalize_result(result)

    def forwarder(self, tool: McpTool) -> Any:
        name = tool.name

        def forward(**values: Any) -> Any:
            extra = values.pop(EXTRA_PARAMETER, None)
            arguments = {key: value for key, value in values.items() if value is not omitted()}
            if isinstance(extra, dict):
                arguments.update(cast("dict[str, Any]", extra))
            return self.forward(name, arguments)

        forward.__signature__ = forwarder_signature(tool)  # type: ignore[attr-defined]
        forward.__name__ = "mcp_tool"
        forward.__qualname__ = "mcp_tool"
        return forward

    def register(self) -> None:
        """Registers every listed tool, so Gazua calls it through its wrapper."""
        from gazua.integration.proxy import make_proxy
        from gazua.integration.registry import registry

        inventory = self.inventory
        if inventory is None:
            raise McpRunBlocked("mcp_transport_lost")
        for tool in inventory.tools:
            original = self.forwarder(tool)
            registry.register(tool.name, original, make_proxy(tool.name, original), is_async=False)


def keep_new_tools_in_dry_run(session_path: Path, names: Iterable[str]) -> None:
    """Rewrites the attempt's session so tools listed after planning stay in dry-run."""
    from gazua.runtime.evidence import write_atomic

    chosen = set(names)
    if not chosen:
        return
    document = cast("dict[str, Any]", json.loads(session_path.read_text(encoding="utf-8")))
    tools = cast("dict[str, Any]", document.get("tools", {}))
    changed = False
    for name in chosen:
        policy: object = tools.get(name)
        if not isinstance(policy, dict):
            continue
        fields = cast("dict[str, Any]", policy)
        if fields.get("dry_run") is False:
            fields["dry_run"] = True
            changed = True
    if changed:
        write_atomic(session_path, json.dumps(document, ensure_ascii=True, indent=2) + "\n")


@contextlib.contextmanager
def mcp_runtime(
    config: GazuaConfig,
    project_root: Path,
    session_path: Path,
    *,
    approved: Mapping[str, str] | None,
    dependent: Iterable[str] = (),
    timeout: float = STARTUP_SECONDS,
) -> Generator[McpRuntime]:
    """A started, registered session for one attempt, closed on the way out."""
    runtime = McpRuntime(
        config, project_root, approved=approved, dependent=dependent, timeout=timeout
    )
    try:
        runtime.start()
        keep_new_tools_in_dry_run(session_path, runtime.new)
        runtime.register()
        yield runtime
    finally:
        runtime.close()


def describe_server(config: GazuaConfig, project_root: Path, timeout: float) -> dict[str, Any]:
    """The reconciled inventory and the snapshot, read without calling any tool."""
    runtime = McpRuntime(config, project_root, approved=None, timeout=timeout)
    try:
        inventory = runtime.start()
    finally:
        runtime.close()
    return reconcile(config, inventory).model_dump(mode="json")
