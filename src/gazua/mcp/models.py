"""Contracts of the MCP adapter: limits, the inventory snapshot and the delivery channel.

Nothing here imports the MCP SDK, so the supervisor, the planners and the verdict engine read
these models without the extra. Tool definitions are the server's data: they are hashed and
compared, never interpreted as templates or as permissions.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Final, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from gazua.runtime.run_models import GazuaId

ACCEPTED_PROTOCOL_VERSIONS: Final = ("2025-06-18", "2025-11-25")
STARTUP_SECONDS: Final = 30.0
GRACEFUL_SECONDS: Final = 2.0
MAX_PAGES: Final = 100
MAX_TOOLS: Final = 1000
MAX_MESSAGE_BYTES: Final = 1024 * 1024
MAX_INVENTORY_BYTES: Final = 8 * 1024 * 1024
DELIVERY_FILE: Final = "mcp-delivery.jsonl"
BROKER_FILE: Final = "mcp-broker.json"
MAX_DELIVERY_BYTES: Final = 4 * 1024 * 1024
MAX_DELIVERY_EVENTS: Final = 10_000
_DEFINITION_KEYS: Final = ("name", "description", "inputSchema", "outputSchema", "annotations")


class McpError(Exception):
    """A failure of the MCP transport or inventory. ``code`` is a short public code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class McpTool(_Strict):
    """One upstream tool definition and the SHA-256 of its canonical JSON."""

    name: Annotated[str, Field(min_length=1)]
    description: str | None = None
    input_schema: dict[str, JsonValue]
    output_schema: dict[str, JsonValue] | None = None
    annotations: dict[str, JsonValue] | None = None
    digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

    def definition(self) -> dict[str, Any]:
        """The definition as MCP sends it, without fields the snapshot does not keep."""
        document: dict[str, Any] = {"name": self.name, "inputSchema": self.input_schema}
        if self.description is not None:
            document["description"] = self.description
        if self.output_schema is not None:
            document["outputSchema"] = self.output_schema
        if self.annotations is not None:
            document["annotations"] = self.annotations
        return document


def tool_from_definition(definition: Mapping[str, Any]) -> McpTool:
    """A snapshot entry. Raises ``McpError`` when the definition breaks the MCP contract."""
    name = definition.get("name")
    description = definition.get("description")
    schema = definition.get("inputSchema")
    output = definition.get("outputSchema")
    annotations = definition.get("annotations")
    if not isinstance(name, str) or not name or not name.isprintable():
        raise McpError("mcp_inventory_invalid")
    if description is not None and not isinstance(description, str):
        raise McpError("mcp_inventory_invalid")
    if not isinstance(schema, dict):
        raise McpError("mcp_inventory_invalid")
    if output is not None and not isinstance(output, dict):
        raise McpError("mcp_inventory_invalid")
    if annotations is not None and not isinstance(annotations, dict):
        raise McpError("mcp_inventory_invalid")
    kept = {key: definition.get(key) for key in _DEFINITION_KEYS}
    schema = cast("dict[str, Any]", schema)
    output = None if output is None else cast("dict[str, Any]", output)
    annotations = None if annotations is None else cast("dict[str, Any]", annotations)
    try:
        text = canonical_json(kept)
        return McpTool.model_validate(
            {
                "name": name,
                "description": description,
                "input_schema": json.loads(canonical_json(schema)),
                "output_schema": None if output is None else json.loads(canonical_json(output)),
                "annotations": None
                if annotations is None
                else json.loads(canonical_json(annotations)),
                "digest": _digest(text),
            }
        )
    except (TypeError, ValueError):
        raise McpError("mcp_inventory_invalid") from None


class McpInventory(_Strict):
    """Every tool one complete ``tools/list`` returned, in name order.

    ``digest`` covers the tools' digests only, so page order and page sizes never change it.
    """

    protocol_version: Annotated[str, Field(min_length=1)]
    tools: list[McpTool] = Field(default_factory=list[McpTool])
    digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

    def get(self, name: str) -> McpTool | None:
        return next((tool for tool in self.tools if tool.name == name), None)

    def digests(self) -> dict[str, str]:
        return {tool.name: tool.digest for tool in self.tools}


def inventory_from(protocol_version: str, tools: Iterable[McpTool]) -> McpInventory:
    """The snapshot of one complete listing. Duplicate names fail: nothing is partial."""
    ordered = sorted(tools, key=lambda tool: tool.name)
    names = [tool.name for tool in ordered]
    if len(set(names)) != len(names):
        raise McpError("mcp_inventory_invalid")
    digest = _digest(canonical_json([[tool.name, tool.digest] for tool in ordered]))
    return McpInventory(protocol_version=protocol_version, tools=ordered, digest=digest)


def changed_tools(approved: Mapping[str, str], current: McpInventory) -> list[str]:
    """Approved names whose definition changed or that are gone from the current listing."""
    found = current.digests()
    return sorted(name for name, digest in approved.items() if found.get(name) != digest)


def new_tools(approved: Mapping[str, str], current: McpInventory) -> list[str]:
    """Listed names the approved snapshot did not have; they stay in dry-run for this run."""
    return sorted(tool.name for tool in current.tools if tool.name not in approved)


@dataclass(frozen=True, slots=True)
class McpLaunch:
    """How one MCP server starts: an executable and its argument vector, without a shell."""

    command: str
    args: tuple[str, ...]
    cwd: Path

    @property
    def display(self) -> str:
        """The command for diagnostics: the executable's name and how many arguments it has.

        Argument values can hold tokens or private paths, so they are never printed.
        """
        name = Path(self.command).name or self.command
        count = len(self.args)
        noun = "argument" if count == 1 else "arguments"
        return f"{name} ({count} {noun})"


DeliverySurface = Literal["description", "result"]


class DeliveryEvent(_Strict):
    """One attack text written to the agent's MCP client, or why it could not be."""

    schema_version: Literal[1]
    kind: Literal["delivery"]
    execution_id: GazuaId
    order: Annotated[int, Field(ge=1)]
    injection_id: Annotated[str, Field(min_length=1)]
    turn: Annotated[int, Field(ge=1)]
    tool: Annotated[str, Field(min_length=1)]
    surface: DeliverySurface
    delivered: bool
    reason: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$")] | None
    call_seq: Annotated[int, Field(ge=1)] | None = None


class CallEvent(_Strict):
    """Where a call of the native call log falls in the broker's order."""

    schema_version: Literal[1]
    kind: Literal["call"]
    execution_id: GazuaId
    order: Annotated[int, Field(ge=1)]
    call_seq: Annotated[int, Field(ge=1)]


DELIVERY_SCHEMA_FILE: Final = "mcp-delivery-v1.schema.json"
_SCHEMA_BASE: Final = "https://raw.githubusercontent.com/JoaoVictorVM/gazua/main/src/gazua/schemas/"


def build_delivery_json_schema() -> dict[str, Any]:
    """One line of the private delivery channel: a delivery or a call's position."""
    from pydantic import TypeAdapter

    schema = TypeAdapter(DeliveryEvent | CallEvent).json_schema(mode="validation")
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": _SCHEMA_BASE + DELIVERY_SCHEMA_FILE,
        "title": "Gazua MCP delivery event",
        **schema,
    }


def render_delivery_json_schema() -> str:
    return json.dumps(build_delivery_json_schema(), indent=2) + "\n"


def packaged_delivery_json_schema() -> str:
    from importlib.resources import files

    return files("gazua").joinpath(f"schemas/{DELIVERY_SCHEMA_FILE}").read_text(encoding="utf-8")
