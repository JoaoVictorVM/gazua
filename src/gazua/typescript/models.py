"""Contracts of the TypeScript adapter: the runner protocol, its limits and the run provenance.

The protocol is local and versioned. Each line is one UTF-8 JSON object of at most 1 MiB and
32 levels, with exactly the keys of its type. The npm runner applies the same rules to the
same corpus, so both sides accept and refuse the same lines.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, Final, Literal, TypeAlias, cast

from pydantic import BaseModel, ConfigDict, Field, JsonValue, TypeAdapter, ValidationError

PROTOCOL_VERSION: Final = 1
MAX_LINE_BYTES: Final = 1024 * 1024
MAX_DEPTH: Final = 32
MAX_RETRY_AFTER: Final = 3600
MAX_TOOLS: Final = 1024
MINIMUM_NODE_MAJOR: Final = 22

RequestId = Annotated[str, Field(pattern=r"^[1-9][0-9]{0,15}$")]
ExportName = Annotated[str, Field(pattern=r"^[A-Za-z_$][A-Za-z0-9_$]{0,127}$")]
ErrorCode = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
ErrorType = Annotated[str, Field(pattern=r"^[A-Za-z_$][A-Za-z0-9_$]{0,127}$")]
Version = Annotated[str, Field(pattern=r"^[0-9A-Za-z.+-]{1,64}$")]
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class _Message(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    protocol_version: Literal[1]
    request_id: RequestId


class RunnerExports(BaseModel):
    """The names the configuration gives to the target module's exports."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    entrypoint: ExportName
    reset: ExportName | None
    as_user: ExportName | None
    output_sink: ExportName | None


class RunnerOpen(_Message):
    type: Literal["open"]
    operation: Literal["run", "describe"]
    module: Annotated[str, Field(min_length=1, max_length=4096)]
    exports: RunnerExports


class RunnerInvoke(_Message):
    type: Literal["invoke"]
    message: str
    armed_injection_id: Annotated[str, Field(min_length=1, max_length=512)] | None


class RunnerReset(_Message):
    type: Literal["reset"]


class RunnerSink(_Message):
    type: Literal["sink"]
    value: JsonValue


class RunnerClose(_Message):
    type: Literal["close"]


class RunnerTool(BaseModel):
    """One tool the runner found registered through ``wrap`` or ``tool``."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    name: Annotated[str, Field(min_length=1, max_length=256)]
    supports_sync: bool
    supports_async: bool
    argument_style: Literal["none", "object"]
    ambiguous: bool


class RunnerReady(_Message):
    type: Literal["ready"]
    sdk_version: Version
    node_version: Version
    tools: Annotated[list[RunnerTool], Field(max_length=MAX_TOOLS)]


class RunnerResult(_Message):
    type: Literal["result"]
    response: str


class RunnerResetDone(_Message):
    type: Literal["reset_done"]


class RunnerSinkResult(_Message):
    type: Literal["sink_result"]
    effect: bool
    proof: Annotated[dict[str, JsonValue], Field(min_length=1)]


class RunnerClosed(_Message):
    type: Literal["closed"]


class RunnerError(_Message):
    """A failure the runner normalized. Codes and class names only, never text of the target."""

    type: Literal["error"]
    code: ErrorCode
    error_type: ErrorType | None
    retry_after: Annotated[float, Field(ge=0, le=MAX_RETRY_AFTER, allow_inf_nan=False)] | None


ToRunner: TypeAlias = Annotated[
    RunnerOpen | RunnerInvoke | RunnerReset | RunnerSink | RunnerClose,
    Field(discriminator="type"),
]
ToPython: TypeAlias = Annotated[
    RunnerReady | RunnerResult | RunnerResetDone | RunnerSinkResult | RunnerClosed | RunnerError,
    Field(discriminator="type"),
]
Direction: TypeAlias = Literal["to_runner", "to_python"]

_TO_RUNNER: TypeAdapter[ToRunner] = TypeAdapter(ToRunner)
_TO_PYTHON: TypeAdapter[ToPython] = TypeAdapter(ToPython)


class ProtocolViolation(Exception):
    """A line that breaks the protocol. ``reason`` is a short code; the line is never kept."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _reject_constant(name: str) -> object:
    raise ValueError(name)


def within_depth(value: object, maximum: int = MAX_DEPTH, depth: int = 0) -> bool:
    if isinstance(value, dict):
        items: list[object] = list(cast("dict[str, object]", value).values())
    elif isinstance(value, list):
        items = cast("list[object]", value)
    else:
        return True
    if depth >= maximum:
        return False
    return all(within_depth(item, maximum, depth + 1) for item in items)


def parse_line(line: bytes) -> dict[str, Any]:
    """Decodes one line, without its newline, into a JSON object."""
    if len(line) > MAX_LINE_BYTES:
        raise ProtocolViolation("protocol_line_too_long")
    try:
        text = line.decode("utf-8")
    except UnicodeDecodeError:
        raise ProtocolViolation("protocol_encoding") from None
    try:
        value = json.loads(text, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        raise ProtocolViolation("protocol_json") from None
    if not isinstance(value, dict):
        raise ProtocolViolation("protocol_json")
    document = cast("dict[str, Any]", value)
    if not within_depth(document):
        raise ProtocolViolation("protocol_depth")
    return document


def validate_message(direction: Direction, value: dict[str, Any]) -> BaseModel:
    """Checks a parsed message of ``direction`` and returns its model."""
    adapter: TypeAdapter[Any] = _TO_RUNNER if direction == "to_runner" else _TO_PYTHON
    # Literal[1] alone would accept true, which the npm side refuses.
    if type(value.get("protocol_version")) is not int:
        raise ProtocolViolation("protocol_version")
    try:
        message = cast("BaseModel", adapter.validate_python(value))
    except ValidationError:
        raise ProtocolViolation("protocol_fields") from None
    if isinstance(message, RunnerReady):
        names = [tool.name for tool in message.tools]
        if len(set(names)) != len(names):
            raise ProtocolViolation("protocol_duplicate_tool")
    return message


def decode(direction: Direction, line: bytes) -> BaseModel:
    return validate_message(direction, parse_line(line))


def encode(message: BaseModel) -> bytes:
    """One line for the runner, newline included."""
    content = json.dumps(
        message.model_dump(mode="json"), ensure_ascii=False, allow_nan=False, separators=(",", ":")
    ).encode("utf-8")
    if len(content) > MAX_LINE_BYTES:
        raise ProtocolViolation("protocol_line_too_long")
    return content + b"\n"


class TypeScriptProvenance(BaseModel):
    """What a TypeScript run was measured against, without paths, sources or arguments.

    The hash covers the bytes of the compiled module loaded at the start of each attempt; every
    attempt of one run agrees on it.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    protocol_version: Literal[1]
    sdk_version: Version
    node_version: Version
    module_sha256: Sha256


def build_protocol_json_schema() -> dict[str, Any]:
    from gazua.config.models import SCHEMA_DIALECT

    base = "https://raw.githubusercontent.com/JoaoVictorVM/gazua/main/src/gazua/schemas/"
    return {
        "$schema": SCHEMA_DIALECT,
        "$id": base + "typescript-runner-v1.schema.json",
        "title": "Gazua TypeScript runner protocol",
        "type": "object",
        "properties": {
            "to_runner": TypeAdapter(ToRunner).json_schema(mode="validation"),
            "to_python": TypeAdapter(ToPython).json_schema(mode="validation"),
        },
    }


def render_protocol_json_schema() -> str:
    return json.dumps(build_protocol_json_schema(), indent=2) + "\n"


__all__ = [
    "MAX_LINE_BYTES",
    "MINIMUM_NODE_MAJOR",
    "PROTOCOL_VERSION",
    "ProtocolViolation",
    "RunnerClose",
    "RunnerError",
    "RunnerExports",
    "RunnerInvoke",
    "RunnerOpen",
    "RunnerReady",
    "RunnerReset",
    "RunnerResult",
    "RunnerSink",
    "RunnerSinkResult",
    "RunnerTool",
    "TypeScriptProvenance",
    "decode",
    "encode",
    "parse_line",
    "validate_message",
]
