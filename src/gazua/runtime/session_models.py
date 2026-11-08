"""Gazua side models of the session file and of one call log record.

The wrapper in ``gazua.integration`` reads and writes the same shapes with the standard
library only. The JSON Schemas generated here are the published contract, so other wrappers
can implement it without Python.
"""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from gazua.config.models import SCHEMA_DIALECT, ArgumentName, Reference

SESSION_SCHEMA_FILE = "session-v1.schema.json"
SESSION_V2_SCHEMA_FILE = "session-v2.schema.json"
CALL_RECORD_SCHEMA_FILE = "call-record-v1.schema.json"
_SCHEMA_BASE = "https://raw.githubusercontent.com/JoaoVictorVM/gazua/main/src/gazua/schemas/"

NonEmptyText = Annotated[str, Field(min_length=1)]


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class SessionActor(_Contract):
    """Who calls the tools during this execution."""

    id: NonEmptyText
    role: Literal["attacker", "victim"]


class SessionTool(_Contract):
    """What the wrapper does with one tool. Gazua computes ``dry_run`` from the declarations."""

    dry_run: bool
    actor_arg: ArgumentName | None
    has_dry_run_return: bool
    dry_run_return: JsonValue


class SessionInjection(_Contract):
    """Attack text appended to text results of one tool."""

    id: NonEmptyText
    tool: NonEmptyText
    text: str
    max_deliveries: Annotated[int, Field(ge=1)]


class SessionDocument(_Contract):
    """Everything the tested process needs to know about the current execution."""

    model_config = ConfigDict(title="Gazua session")

    schema_version: Literal[1]
    run_id: NonEmptyText
    mode: Literal["tools", "agent"]
    call_log: NonEmptyText
    actor: SessionActor | None
    as_user: Reference | None
    tools: dict[NonEmptyText, SessionTool]
    injections: list[SessionInjection]


class SessionReceiver(_Contract):
    """The local receiver of one execution. The token authenticates the worker's requests."""

    host: Literal["127.0.0.1"]
    port: Annotated[int, Field(ge=1, le=65535)]
    token: NonEmptyText
    execution_id: NonEmptyText


class SessionDocumentV2(_Contract):
    """A session for one supervised execution: version 1 plus its limit and local channels.

    Readers of version 1 reject it, and it is never read as version 1.
    """

    model_config = ConfigDict(title="Gazua execution session")

    schema_version: Literal[2]
    run_id: NonEmptyText
    mode: Literal["tools", "agent"]
    call_log: NonEmptyText
    actor: SessionActor | None
    as_user: Reference | None
    tools: dict[NonEmptyText, SessionTool]
    injections: list[SessionInjection]
    execution_id: NonEmptyText
    max_tool_calls: Annotated[int, Field(ge=1)]
    events_path: NonEmptyText
    receiver: SessionReceiver | None
    usage_reporting: bool


AnySession = SessionDocument | SessionDocumentV2


class RecordActor(_Contract):
    """The identity imposed on a call and how. ``source`` is ``none`` when there was none."""

    id: str | None
    source: Literal["actor_arg", "as_user", "none"]


class RecordError(_Contract):
    type: NonEmptyText


class RecordInjection(_Contract):
    id: NonEmptyText
    delivered: bool
    reason: str | None


class CallRecord(_Contract):
    """One tool call. Return values are never recorded, only their type."""

    model_config = ConfigDict(title="Gazua call record")

    schema_version: Literal[1]
    seq: Annotated[int, Field(ge=1)]
    tool: NonEmptyText
    arguments: dict[str, JsonValue]
    truncated: bool
    actor: RecordActor
    dry_run: bool
    undeclared: bool
    outcome: Literal["returned", "raised", "blocked"]
    low_fidelity: bool
    result_type: str | None
    error: RecordError | None
    block_reason: str | None
    injection: RecordInjection | None


def _schema(model: type[BaseModel], name: str) -> dict[str, Any]:
    schema = model.model_json_schema(mode="validation")
    return {"$schema": SCHEMA_DIALECT, "$id": _SCHEMA_BASE + name, **schema}


def build_session_json_schema() -> dict[str, Any]:
    return _schema(SessionDocument, SESSION_SCHEMA_FILE)


def build_session_v2_json_schema() -> dict[str, Any]:
    return _schema(SessionDocumentV2, SESSION_V2_SCHEMA_FILE)


def build_call_record_json_schema() -> dict[str, Any]:
    return _schema(CallRecord, CALL_RECORD_SCHEMA_FILE)


def render_session_json_schema() -> str:
    return json.dumps(build_session_json_schema(), indent=2) + "\n"


def render_session_v2_json_schema() -> str:
    return json.dumps(build_session_v2_json_schema(), indent=2) + "\n"


def render_call_record_json_schema() -> str:
    return json.dumps(build_call_record_json_schema(), indent=2) + "\n"


def packaged_schema(name: str) -> str:
    """A schema file distributed with this package, read without network access."""
    return files("gazua").joinpath(f"schemas/{name}").read_text(encoding="utf-8")
