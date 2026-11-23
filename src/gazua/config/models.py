"""Typed ``gazua.yaml`` models: the single source of the loader and of the JSON Schema."""

from __future__ import annotations

import ipaddress
import json
import re
from enum import StrEnum
from importlib.resources import files
from typing import Annotated, Any, Final, Literal, LiteralString, TypeVar

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    WithJsonSchema,
)
from pydantic_core import PydanticCustomError

from gazua.config.references import (
    IDENTIFIER_PATTERN,
    REFERENCE_PATTERN,
    is_argument_name,
    is_reference,
)

SCHEMA_VERSION = 1
SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
SCHEMA_URL = (
    "https://raw.githubusercontent.com/JoaoVictorVM/gazua/main/"
    "src/gazua/schemas/config-v1.schema.json"
)

DEFAULT_ALLOWED_TARGETS = ("localhost", "127.0.0.1", "::1")

_TOOL_NAME_PATTERN = r"^[^\x00-\x1f\x7f-\x9f]+$"
_HOSTNAME = r"[A-Za-z0-9_](?:[A-Za-z0-9_.-]*[A-Za-z0-9_])?"
_HOST_PATTERN = rf"^(?:{_HOSTNAME}|[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*)$"
_HOST_MESSAGE: Final = "Expected an exact host, without scheme, path, port or wildcard."

_Item = TypeVar("_Item")


def _invalid(code: LiteralString, message: LiteralString) -> PydanticCustomError:
    return PydanticCustomError(code, message)


def _check_reference(value: str) -> str:
    if not is_reference(value):
        raise _invalid("reference_syntax", "Expected a reference in the form module:attribute.")
    return value


def _check_argument(value: str) -> str:
    if not is_argument_name(value):
        raise _invalid("argument_syntax", "Expected a simple Python argument name.")
    return value


def _check_tool_name(value: str) -> str:
    if not value or not value.isprintable():
        raise _invalid("tool_name", "Tool names must be non-empty, without control characters.")
    return value


def _check_host(value: str) -> str:
    if ":" in value:
        try:
            ipaddress.IPv6Address(value)
        except ValueError:
            raise _invalid("host_syntax", _HOST_MESSAGE) from None
    elif not re.fullmatch(_HOSTNAME, value):
        raise _invalid("host_syntax", _HOST_MESSAGE)
    return value


def _check_unique(values: list[_Item]) -> list[_Item]:
    if any(value in values[:index] for index, value in enumerate(values)):
        raise _invalid("duplicate_item", "Items in this list must be unique.")
    return values


Reference = Annotated[
    str,
    AfterValidator(_check_reference),
    WithJsonSchema({"type": "string", "pattern": REFERENCE_PATTERN}),
]
ArgumentName = Annotated[
    str,
    AfterValidator(_check_argument),
    WithJsonSchema({"type": "string", "pattern": rf"^{IDENTIFIER_PATTERN}$"}),
]
ToolName = Annotated[
    str,
    AfterValidator(_check_tool_name),
    WithJsonSchema({"type": "string", "pattern": _TOOL_NAME_PATTERN}),
]
Host = Annotated[
    str,
    AfterValidator(_check_host),
    WithJsonSchema({"type": "string", "pattern": _HOST_PATTERN}),
]
NonEmptyText = Annotated[str, Field(min_length=1)]
PositiveInt = Annotated[int, Field(gt=0)]
PositiveNumber = Annotated[float, Field(gt=0, allow_inf_nan=False)]
NonNegativeNumber = Annotated[float, Field(ge=0, allow_inf_nan=False)]
Severity = Literal["low", "medium", "high", "critical"]


class _Declaration(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ToolClass(StrEnum):
    FORBIDDEN = "forbidden"
    SENSITIVE = "sensitive"
    REGULAR = "regular"
    UNCLASSIFIED = "unclassified"


def _without_null_default(schema: dict[str, Any]) -> None:
    # Absence and an explicit null mean different things here, and a schema default of null
    # would tell editors that they are the same.
    schema["properties"]["dry_run_return"].pop("default", None)


class Tool(_Declaration):
    """Declaration of one tool. A missing classification is preserved, never assumed false."""

    model_config = ConfigDict(json_schema_extra=_without_null_default)

    safe: bool = False
    sensitive: bool | None = None
    forbidden: bool | None = None
    owner_arg: ArgumentName | None = None
    actor_arg: ArgumentName | None = None
    dry_run_return: JsonValue = None

    @property
    def classification(self) -> ToolClass:
        if self.forbidden is True:
            return ToolClass.FORBIDDEN
        if self.sensitive is True:
            return ToolClass.SENSITIVE
        if self.forbidden is False or self.sensitive is False:
            return ToolClass.REGULAR
        return ToolClass.UNCLASSIFIED

    @property
    def has_dry_run_return(self) -> bool:
        return "dry_run_return" in self.model_fields_set

    @property
    def requires_dry_run(self) -> bool:
        """True while the declarations alone rule out running the real function."""
        return not self.safe or self.classification is ToolClass.UNCLASSIFIED


class Target(_Declaration):
    """References to the target's hooks. They stay as text until an authorized execution."""

    reset: Reference | None = None
    as_user: Reference | None = None


class Limits(_Declaration):
    """Ceilings of a run. Durations are in seconds and costs in USD."""

    max_runs: PositiveInt = 300
    timeout: PositiveNumber = 120
    max_tool_calls: PositiveInt = 50
    concurrency: PositiveInt = 2
    max_cost: PositiveNumber | None = None
    cost_per_run: NonNegativeNumber | None = None


class FixtureRecord(_Declaration):
    """A synthetic record that belongs to an identity."""

    tool: ToolName
    id_arg: ArgumentName
    id: NonEmptyText | int


class Identity(_Declaration):
    """A synthetic identity used by attacks between users."""

    id: NonEmptyText
    records: list[FixtureRecord] = Field(default_factory=list["FixtureRecord"])


class Fixtures(_Declaration):
    """Test identities. Each side is optional because each attack decides what it needs."""

    attacker: Identity | None = None
    victim: Identity | None = None


def _default_fail_on() -> list[Severity]:
    return ["high", "critical"]


class Gate(_Declaration):
    """Severities that fail the gate. An empty list turns the severity gate off."""

    fail_on: Annotated[list[Severity], AfterValidator(_check_unique)] = Field(
        default_factory=_default_fail_on,
        json_schema_extra={"uniqueItems": True, "default": ["high", "critical"]},
    )


class LegitTask(_Declaration):
    """A legitimate request and the tool it is expected to use."""

    request: NonEmptyText
    expected_tool: ToolName


MAX_AGENT_REQUEST_CHARACTERS: Final = 16_384


def _check_request(value: str) -> str:
    if "\x00" in value:
        raise _invalid("invalid_text", "Text cannot contain NUL characters.")
    return value


class AgentEntry(_Declaration):
    """A declared tool that reads content the agent consumes, and the message that triggers it.

    The request is sent as literal text: it is never read as a template.
    """

    tool: ToolName
    request: Annotated[
        str,
        Field(min_length=1, max_length=MAX_AGENT_REQUEST_CHARACTERS),
        AfterValidator(_check_request),
    ]


class AgentEntries(_Declaration):
    """Indirect entries agent mode can reach. An absent entry is reported as not tested.

    ``mcp_tool_description`` names the MCP tool whose description carries the text; it only
    applies to a target declared under ``mcp``.
    """

    tool_result: AgentEntry | None = None
    rag_document: AgentEntry | None = None
    poisoned_memory: AgentEntry | None = None
    mcp_tool_description: AgentEntry | None = None

    def get(self, entry: str) -> AgentEntry | None:
        if entry not in AgentEntries.model_fields:
            return None
        return getattr(self, entry)


MAX_MCP_ARGUMENTS: Final = 128
MAX_MCP_ARGUMENT_CHARACTERS: Final = 8192


def _check_no_nul(value: str) -> str:
    if "\x00" in value:
        raise _invalid("invalid_text", "Text cannot contain NUL characters.")
    return value


McpText = Annotated[str, Field(min_length=1), AfterValidator(_check_no_nul)]
McpArgument = Annotated[
    str, Field(max_length=MAX_MCP_ARGUMENT_CHARACTERS), AfterValidator(_check_no_nul)
]


class McpServer(_Declaration):
    """A local MCP server that Gazua starts over stdio for each attempt.

    ``command`` is one executable and ``args`` its argument vector: no shell reads them, so
    substitutions, pipes and variables are not interpreted. ``cwd`` is relative to the
    ``gazua.yaml`` folder. Starting the server runs its code with the user's permissions.
    """

    transport: Literal["stdio"]
    command: McpText
    args: Annotated[list[McpArgument], Field(max_length=MAX_MCP_ARGUMENTS)] = Field(
        default_factory=list[str]
    )
    cwd: McpText = "."


def _check_endpoint(value: str) -> str:
    from gazua.http.models import EndpointError, parse_endpoint

    try:
        parse_endpoint(value)
    except EndpointError as error:
        raise PydanticCustomError("http_endpoint", "{reason}", {"reason": str(error)}) from None
    return value


def _check_headers(value: dict[str, str]) -> dict[str, str]:
    from gazua.http.models import MAX_HEADERS, header_problem

    if len(value) > MAX_HEADERS:
        raise _invalid("http_header", "At most 32 static headers can be declared.")
    lowered = [name.lower() for name in value]
    if len(set(lowered)) != len(lowered):
        raise _invalid("http_header", "Header names must be unique, ignoring case.")
    for name, text in value.items():
        problem = header_problem(name, text)
        if problem is not None:
            raise PydanticCustomError("http_header", "{reason}", {"reason": problem})
    return value


HttpEndpoint = Annotated[
    str,
    AfterValidator(_check_endpoint),
    WithJsonSchema({"type": "string", "pattern": r"^[Hh][Tt][Tt][Pp][Ss]?://[^\s#@]+$"}),
]


class HttpTarget(_Declaration):
    """An authorized HTTP endpoint agent mode sends each turn to, as ``POST`` JSON.

    There is no dry-run over HTTP: every request can have real effects on the endpoint, so
    ``real_side_effects: i_understand`` and a local authorization receipt are required before
    a run. Headers are static, non-secret values; credentials are out of scope.
    """

    endpoint: HttpEndpoint
    headers: Annotated[dict[str, str], AfterValidator(_check_headers)] = Field(
        default_factory=dict[str, str],
        json_schema_extra={"maxProperties": 32},
    )
    real_side_effects: Literal["i_understand"] | None = None


class TraceConfig(_Declaration):
    """A local OTLP/HTTP receiver that collects the target's tool spans for each attempt."""

    transport: Literal["otlp_http"]
    wait_seconds: Annotated[float, Field(gt=0, le=10, allow_inf_nan=False)] = 5


class MoldSources(_Declaration):
    """Local folders with extra attack molds. Paths are relative to the ``gazua.yaml`` folder.

    Both lists are read the same way and both print a warning before loading, because files
    outside the package are third-party content.
    """

    directories: Annotated[list[NonEmptyText], AfterValidator(_check_unique)] = Field(
        default_factory=list[str], json_schema_extra={"uniqueItems": True}
    )
    external_catalogs: Annotated[list[NonEmptyText], AfterValidator(_check_unique)] = Field(
        default_factory=list[str], json_schema_extra={"uniqueItems": True}
    )


class GazuaConfig(_Declaration):
    """Declarative configuration of a project tested by Gazua."""

    model_config = ConfigDict(title="Gazua configuration")

    schema_version: Literal[1]
    entrypoint: Reference | None = None
    mcp: McpServer | None = None
    http: HttpTarget | None = None
    traces: TraceConfig | None = None
    target: Target = Field(default_factory=Target)
    tools: dict[ToolName, Tool] = Field(
        default_factory=dict[str, Tool],
        json_schema_extra={"propertyNames": {"pattern": _TOOL_NAME_PATTERN}},
    )
    limits: Limits = Field(default_factory=Limits)
    fixtures: Fixtures = Field(default_factory=Fixtures)
    canaries: Annotated[list[NonEmptyText], AfterValidator(_check_unique)] = Field(
        default_factory=list[str], json_schema_extra={"uniqueItems": True}
    )
    output_sink: Reference | None = None
    gate: Gate = Field(default_factory=Gate)
    legit_tasks: list[LegitTask] = Field(default_factory=list[LegitTask])
    agent_entries: AgentEntries = Field(default_factory=AgentEntries)
    allowed_targets: list[Host] = Field(
        default_factory=lambda: list(DEFAULT_ALLOWED_TARGETS),
        json_schema_extra={"default": list(DEFAULT_ALLOWED_TARGETS)},
    )
    molds: MoldSources = Field(default_factory=MoldSources)

    def to_document(self) -> dict[str, Any]:
        """JSON data with only what was declared, so absences survive a round trip."""
        return self.model_dump(mode="json", exclude_unset=True)


def build_json_schema() -> dict[str, Any]:
    schema = GazuaConfig.model_json_schema(mode="validation")
    return {"$schema": SCHEMA_DIALECT, "$id": SCHEMA_URL, **schema}


def packaged_json_schema() -> str:
    """The schema file distributed with this package, read without network access."""
    resource = files("gazua").joinpath("schemas/config-v1.schema.json")
    return resource.read_text(encoding="utf-8")


def render_json_schema() -> str:
    return json.dumps(build_json_schema(), indent=2) + "\n"
