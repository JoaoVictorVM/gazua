"""Decoding keeps only Gazua's tool contract; broken, conflicting or huge batches fail closed."""

from __future__ import annotations

import time

import pytest
from http_support import FORBIDDEN_TOOL, READ_TOOL, SpanSpec, build_batch, require_otel
from hypothesis import given, settings
from hypothesis import strategies as st

RUN = "GAZUA-run-20260101000000-abc123:GAZUA-exec-0001"


@pytest.fixture(autouse=True)
def _otel() -> None:
    require_otel()


def test_only_gazua_tool_attributes_are_retained() -> None:
    from gazua.otel.decoder import decode_batch

    body = build_batch(
        RUN,
        [
            SpanSpec(READ_TOOL, extra={"http.request.body": "secret body", "user.email": "a@b.c"}),
            SpanSpec(FORBIDDEN_TOOL, outcome="blocked"),
            SpanSpec("chat", operation="llm_call"),
            SpanSpec(READ_TOOL, outcome="maybe"),
            SpanSpec(READ_TOOL, run_id="GAZUA-run-other:GAZUA-exec-0002"),
        ],
    )

    batch = decode_batch(body, expected_run=RUN)

    assert [(item.tool, item.outcome) for item in batch.spans] == [
        (READ_TOOL, "succeeded"),
        (FORBIDDEN_TOOL, "blocked"),
    ]
    assert batch.ignored == 1
    assert batch.rejected == 2
    dumped = str([item.model_dump() for item in batch.spans])
    for discarded in ("secret body", "a@b.c", "private prompt", "private-service-name"):
        assert discarded not in dumped
    assert set(batch.spans[0].model_dump()) == {
        "trace_id",
        "span_id",
        "run_id",
        "tool",
        "outcome",
        "started_at",
        "ended_at",
    }


def test_invalid_duplicate_and_oversized_batches_fail_closed() -> None:
    from gazua.otel.decoder import DecodedBatch, TraceDecodeError, decode_batch
    from gazua.otel.evidence import TraceCollector
    from gazua.otel.models import MAX_SPANS, ToolSpanEvidence

    with pytest.raises(TraceDecodeError) as invalid:
        decode_batch(b"\xff\xff\xff\xff", expected_run=RUN)
    assert invalid.value.code == "otel_payload_invalid"

    with pytest.raises(TraceDecodeError) as limit:
        decode_batch(build_batch(RUN, [SpanSpec(READ_TOOL)] * (MAX_SPANS + 1)), expected_run=RUN)
    assert limit.value.code == "otel_payload_limit"

    now = time.time_ns()
    collector = TraceCollector("GAZUA-exec-0001", RUN, now - 10)
    span = ToolSpanEvidence(
        trace_id="1" * 32,
        span_id="2" * 16,
        run_id=RUN,
        tool=FORBIDDEN_TOOL,
        outcome="succeeded",
        started_at=now,
        ended_at=now + 1,
    )
    conflicting = span.model_copy(update={"outcome": "blocked"})
    collector.accept(DecodedBatch(spans=[span]))
    collector.accept(DecodedBatch(spans=[span]))
    collector.accept(DecodedBatch(spans=[conflicting]))
    collector.close()

    evidence = collector.evidence()
    assert evidence.accepted == 1
    assert evidence.duplicates == 1
    assert not evidence.complete
    assert evidence.reason == "otel_trace_conflict"


def test_an_open_or_failed_channel_is_never_complete() -> None:
    from gazua.otel.evidence import TraceCollector

    collector = TraceCollector("GAZUA-exec-0001", RUN, time.time_ns())
    assert not collector.evidence().complete
    collector.fail("otel_unauthorized")
    collector.close()
    evidence = collector.evidence()
    assert not evidence.complete
    assert evidence.reason == "otel_unauthorized"


@settings(max_examples=60, deadline=None)
@given(
    outcomes=st.lists(st.sampled_from(["succeeded", "raised", "blocked"]), max_size=6),
    offsets=st.lists(st.integers(min_value=-5, max_value=5), min_size=6, max_size=6),
    fail=st.sampled_from([None, "otel_unauthorized", "otel_payload_invalid", "otel_payload_limit"]),
    closed=st.booleans(),
)
def test_incomplete_evidence_never_supports_a_negative(
    outcomes: list[str], offsets: list[int], fail: str | None, closed: bool
) -> None:
    from gazua.otel.decoder import DecodedBatch
    from gazua.otel.evidence import TraceCollector
    from gazua.otel.models import ToolSpanEvidence

    start = 1_000_000_000_000
    collector = TraceCollector("GAZUA-exec-0001", RUN, start)
    spans = [
        ToolSpanEvidence(
            trace_id="a" * 32,
            span_id=f"{index:016x}",
            run_id=RUN,
            tool=FORBIDDEN_TOOL,
            outcome=outcome,  # type: ignore[arg-type]
            started_at=start + offsets[index] * 1_000,
            ended_at=start + offsets[index] * 1_000 + 1,
        )
        for index, outcome in enumerate(outcomes)
    ]
    collector.accept(DecodedBatch(spans=spans))
    if fail is not None:
        collector.fail(fail)
    if closed:
        collector.close()

    evidence = collector.evidence()

    assert evidence.accepted == len(evidence.tool_spans)
    assert all(item.started_at >= start for item in evidence.tool_spans)
    assert evidence.late == sum(1 for offset in offsets[: len(outcomes)] if offset < 0)
    if fail is not None or not closed:
        assert not evidence.complete
        assert evidence.reason is not None
