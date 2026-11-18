"""Reconciles an MCP inventory with the declarations of ``gazua.yaml``.

The planners read the result as a regular tool inventory: an input schema's properties become
keyword parameters, so the existing argument checks apply. Nothing here imports the SDK, and no
argument is synthesized for a required property that a binding does not provide.
"""

from __future__ import annotations

import inspect
import keyword
from pathlib import Path
from typing import Any, Final, cast

from gazua.config.models import GazuaConfig, McpServer, ToolClass
from gazua.mcp.models import McpInventory, McpLaunch, McpTool
from gazua.mcp.policy import schema_problem
from gazua.modes.tools_models import ToolsInventory

EXTRA_PARAMETER: Final = "_gazua_extra"
_OMITTED: Final = object()


def omitted() -> object:
    """The default of an optional parameter the caller did not give; it is never sent."""
    return _OMITTED


def launch_for(server: McpServer, config_folder: Path) -> McpLaunch:
    """The launch of a declared server; ``cwd`` is relative to the configuration's folder."""
    return McpLaunch(
        command=server.command,
        args=tuple(server.args),
        cwd=(config_folder / server.cwd).resolve(),
    )


def _plain(name: str) -> bool:
    return name.isidentifier() and not keyword.iskeyword(name)


def forwarder_signature(tool: McpTool) -> inspect.Signature:
    """Keyword-only parameters for the schema's properties, and ``**`` for anything else.

    Optional properties default to a marker that is dropped before the call, so the server
    never receives a value nobody chose. Names that Python cannot hold go through ``**``.
    """
    schema = tool.input_schema
    properties = cast("dict[str, object]", schema.get("properties") or {})
    required = set(cast("list[str]", schema.get("required") or []))
    parameters: list[inspect.Parameter] = []
    open_ended = schema.get("additionalProperties", True) is not False
    for name in sorted(properties):
        if not _plain(name) or name == EXTRA_PARAMETER:
            open_ended = True
            continue
        default = inspect.Parameter.empty if name in required else _OMITTED
        parameters.append(inspect.Parameter(name, inspect.Parameter.KEYWORD_ONLY, default=default))
    if open_ended:
        parameters.append(inspect.Parameter(EXTRA_PARAMETER, inspect.Parameter.VAR_KEYWORD))
    return inspect.Signature(parameters)


def reconcile(config: GazuaConfig, inventory: McpInventory) -> ToolsInventory:
    """Every declared or listed name, as the planners read tools, plus the snapshot itself."""
    from gazua.runtime.tools import signature_description

    names = sorted(set(config.tools) | {tool.name for tool in inventory.tools})
    tools: list[dict[str, Any]] = []
    for name in names:
        declaration = config.tools.get(name)
        listed = inventory.get(name)
        diagnostics: list[str] = []
        described: dict[str, Any] = {
            "name": name,
            "registered": listed is not None,
            "safe": declaration is not None and declaration.safe,
            "classified": declaration is not None
            and declaration.classification is not ToolClass.UNCLASSIFIED,
            "ambiguous": False,
            "signature_available": False,
            "supports_sync": listed is not None,
            "supports_async": False,
        }
        if listed is None:
            diagnostics.append("tool_not_found")
        else:
            if declaration is None:
                diagnostics.append("tool_undeclared")
            problem = schema_problem(listed.input_schema)
            if problem is not None:
                diagnostics.append(problem)
            else:
                described.update(signature_description(_shaped(listed)))
        described["diagnostics"] = diagnostics
        tools.append(described)
    return ToolsInventory.model_validate(
        {"complete": True, "tools": tools, "mcp": inventory.model_dump(mode="json")}
    )


def _shaped(tool: McpTool) -> Any:
    def forward(**_: Any) -> None:
        return None

    forward.__signature__ = forwarder_signature(tool)  # type: ignore[attr-defined]
    return forward


def undeclared_names(config: GazuaConfig, inventory: McpInventory) -> list[str]:
    """Listed tools without a declaration: dry-run, with a warning, never forwarded."""
    return [tool.name for tool in inventory.tools if tool.name not in config.tools]


def approved_digests(document: object) -> dict[str, str] | None:
    """The tool digests a request carries from planning, checked as plain strings."""
    if document is None:
        return None
    if not isinstance(document, dict):
        raise ValueError("mcp_snapshot_invalid")
    approved: dict[str, str] = {}
    for name, digest in cast("dict[object, object]", document).items():
        if not isinstance(name, str) or not isinstance(digest, str) or len(digest) != 64:
            raise ValueError("mcp_snapshot_invalid")
        approved[name] = digest
    return approved
