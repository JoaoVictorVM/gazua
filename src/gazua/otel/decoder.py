"""Decodes one ``ExportTraceServiceRequest`` and keeps only Gazua's tool span contract.

A span is a tool call only when ``gazua.operation`` is exactly ``tool_call`` and the tool,
outcome and attempt attributes are present and valid. Nothing else of the batch outlives this
function: other attributes, resources, scopes, events, links and status texts are never copied.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from gazua.otel.models import (
    MAX_SPANS,
    OPERATION_ATTRIBUTE,
    OUTCOME_ATTRIBUTE,
    RUN_ATTRIBUTE,
    SPAN_OUTCOMES,
    TOOL_ATTRIBUTE,
    TOOL_CALL,
    ToolSpanEvidence,
)

_GAZUA_ATTRIBUTES = frozenset(
    {OPERATION_ATTRIBUTE, TOOL_ATTRIBUTE, OUTCOME_ATTRIBUTE, RUN_ATTRIBUTE}
)
MAX_ATTRIBUTE_CHARACTERS = 256


class TraceDecodeError(ValueError):
    """The batch is not usable. ``code`` is ``otel_payload_invalid`` or ``otel_payload_limit``."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(slots=True)
class DecodedBatch:
    spans: list[ToolSpanEvidence] = field(default_factory=list[ToolSpanEvidence])
    rejected: int = 0
    ignored: int = 0


def _text(value: Any) -> str | None:
    if value.WhichOneof("value") != "string_value":
        return None
    text = str(value.string_value)
    if not text or len(text) > MAX_ATTRIBUTE_CHARACTERS or not text.isprintable():
        return None
    return text


def _gazua_attributes(span: Any) -> dict[str, str | None]:
    found: dict[str, str | None] = {}
    for item in span.attributes:
        key = str(item.key)
        if key in _GAZUA_ATTRIBUTES:
            # A repeated key is ambiguous, so the span cannot follow the contract.
            found[key] = None if key in found else _text(item.value)
    return found


def _span(span: Any, expected_run: str) -> ToolSpanEvidence | None:
    attributes = _gazua_attributes(span)
    tool = attributes.get(TOOL_ATTRIBUTE)
    outcome = attributes.get(OUTCOME_ATTRIBUTE)
    run = attributes.get(RUN_ATTRIBUTE)
    trace_id, span_id = bytes(span.trace_id), bytes(span.span_id)
    if (
        tool is None
        or outcome not in SPAN_OUTCOMES
        or run is None
        or run != expected_run
        or len(trace_id) != 16
        or len(span_id) != 8
        or not any(trace_id)
        or not any(span_id)
    ):
        return None
    started, ended = int(span.start_time_unix_nano), int(span.end_time_unix_nano)
    if started <= 0 or ended < started:
        return None
    return ToolSpanEvidence(
        trace_id=trace_id.hex(),
        span_id=span_id.hex(),
        run_id=run,
        tool=tool,
        outcome=outcome,
        started_at=started,
        ended_at=ended,
    )


def decode_batch(body: bytes, *, expected_run: str) -> DecodedBatch:
    """The tool spans of one OTLP/HTTP protobuf body for this attempt.

    Spans of another attempt count as rejected; spans that are not tool calls are ignored.
    """
    from google.protobuf.message import DecodeError
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
        ExportTraceServiceRequest,
    )

    request = ExportTraceServiceRequest()
    try:
        request.ParseFromString(body)
    except (DecodeError, RecursionError, ValueError):
        raise TraceDecodeError("otel_payload_invalid") from None
    batch = DecodedBatch()
    total = 0
    for resource in request.resource_spans:
        for scope in resource.scope_spans:
            for span in scope.spans:
                total += 1
                if total > MAX_SPANS:
                    raise TraceDecodeError("otel_payload_limit")
                operation = _gazua_attributes(span).get(OPERATION_ATTRIBUTE)
                if operation != TOOL_CALL:
                    batch.ignored += 1
                    continue
                found = _span(span, expected_run)
                if found is None:
                    batch.rejected += 1
                else:
                    batch.spans.append(found)
    return batch


def empty_response() -> bytes:
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
        ExportTraceServiceResponse,
    )

    return ExportTraceServiceResponse().SerializeToString()


__all__ = ["DecodedBatch", "TraceDecodeError", "decode_batch", "empty_response"]
