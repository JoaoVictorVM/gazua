"""The minimal evidence kept from tool spans, and the limits of one attempt's trace channel.

Only the identity, timing, tool, outcome and attempt of each recognized span survive decoding.
Resource and scope attributes, events, links, status texts and every other attribute are
dropped as soon as a batch is read. An incomplete channel never proves that a tool was not
called.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, Final, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, model_validator

MAX_BATCH_BYTES: Final = 4 * 1024 * 1024
MAX_SPANS: Final = 10_000
TRACE_SCHEMA_FILE: Final = "http-trace-evidence-v1.schema.json"
TOOL_CALL: Final = "tool_call"
OPERATION_ATTRIBUTE: Final = "gazua.operation"
TOOL_ATTRIBUTE: Final = "gazua.tool.name"
OUTCOME_ATTRIBUTE: Final = "gazua.tool.outcome"
RUN_ATTRIBUTE: Final = "gazua.run_id"
_SCHEMA_BASE: Final = "https://raw.githubusercontent.com/JoaoVictorVM/gazua/main/src/gazua/schemas/"

SpanOutcome: TypeAlias = Literal["succeeded", "raised", "blocked"]
SPAN_OUTCOMES: Final = ("succeeded", "raised", "blocked")
Code = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$")]
Count = Annotated[int, Field(ge=0)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ToolSpanEvidence(_Strict):
    """One recognized tool call span. Timestamps are Unix nanoseconds from the target's clock."""

    trace_id: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
    span_id: Annotated[str, Field(pattern=r"^[0-9a-f]{16}$")]
    run_id: Annotated[str, Field(min_length=1, max_length=256)]
    tool: Annotated[str, Field(min_length=1, max_length=256)]
    outcome: SpanOutcome
    started_at: Count
    ended_at: Count

    @model_validator(mode="after")
    def _ordered(self) -> ToolSpanEvidence:
        if self.started_at > self.ended_at:
            raise ValueError("A span cannot end before it starts.")
        return self

    @property
    def identity(self) -> tuple[str, str]:
        return self.trace_id, self.span_id


class TraceEvidence(_Strict):
    """What one attempt's receiver saw. ``complete`` is the only flag a negative may rely on.

    ``accepted`` counts recognized tool spans kept, ``rejected`` spans with a broken or foreign
    contract, ``late`` spans outside the attempt's window and ``ignored`` other spans.
    """

    model_config = ConfigDict(title="Gazua HTTP trace evidence")

    schema_version: Literal[1]
    execution_id: Annotated[str, Field(min_length=1, max_length=64)]
    complete: bool
    receiver_closed: bool
    accepted: Count
    rejected: Count
    duplicates: Count
    late: Count
    ignored: Count
    truncated: bool
    reason: Code | None = None
    tool_spans: Annotated[list[ToolSpanEvidence], Field(max_length=MAX_SPANS)] = Field(
        default_factory=list[ToolSpanEvidence]
    )

    @model_validator(mode="after")
    def _coherent(self) -> TraceEvidence:
        if self.accepted != len(self.tool_spans):
            raise ValueError("accepted counts the kept tool spans.")
        identities = [item.identity for item in self.tool_spans]
        if len(set(identities)) != len(identities):
            raise ValueError("Each span identity appears once.")
        if self.complete and (self.truncated or not self.receiver_closed or self.reason):
            raise ValueError("A complete channel is closed, untruncated and has no reason.")
        return self

    def has_tool_contract(self) -> bool:
        """True once the target exported at least one span that follows the tool contract."""
        return bool(self.tool_spans)


def build_trace_json_schema() -> dict[str, Any]:
    from gazua.config.models import SCHEMA_DIALECT

    schema = TraceEvidence.model_json_schema(mode="validation")
    return {"$schema": SCHEMA_DIALECT, "$id": _SCHEMA_BASE + TRACE_SCHEMA_FILE, **schema}


def render_trace_json_schema() -> str:
    return json.dumps(build_trace_json_schema(), indent=2) + "\n"


__all__ = [
    "MAX_BATCH_BYTES",
    "MAX_SPANS",
    "SPAN_OUTCOMES",
    "TRACE_SCHEMA_FILE",
    "ToolSpanEvidence",
    "TraceEvidence",
    "render_trace_json_schema",
]
