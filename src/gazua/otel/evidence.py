"""Correlates one attempt's tool spans, deduplicates them and writes the private sidecar.

Spans are attributed only when they carry this attempt's id and start after its first request.
The same identity seen twice with the same content is a duplicate; with different content it
is a conflict, and the channel is no longer complete. The sidecar lives in the attempt's
private folder and is deleted with it.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

from gazua.otel.decoder import DecodedBatch
from gazua.otel.models import MAX_SPANS, ToolSpanEvidence, TraceEvidence


class TraceCollector:
    """Thread-safe store of one attempt's spans while its receiver is open."""

    def __init__(self, execution_id: str, attempt_id: str, window_start_ns: int) -> None:
        self.execution_id = execution_id
        self.attempt_id = attempt_id
        self.window_start_ns = window_start_ns
        self._lock = threading.Lock()
        self._spans: dict[tuple[str, str], ToolSpanEvidence] = {}
        self._rejected = 0
        self._duplicates = 0
        self._late = 0
        self._ignored = 0
        self._truncated = False
        self._reason: str | None = None
        self._closed = False
        self.last_activity = time.monotonic()

    def fail(self, code: str) -> None:
        """A batch was refused: whatever it held is lost, so the channel is incomplete."""
        with self._lock:
            if self._reason is None:
                self._reason = code
            if code == "otel_payload_limit":
                self._truncated = True
            self.last_activity = time.monotonic()

    def accept(self, batch: DecodedBatch) -> None:
        with self._lock:
            if self._closed:
                self._late += len(batch.spans)
                return
            self._rejected += batch.rejected
            self._ignored += batch.ignored
            for span in batch.spans:
                if span.started_at < self.window_start_ns:
                    self._late += 1
                    continue
                seen = self._spans.get(span.identity)
                if seen is not None:
                    if seen == span:
                        self._duplicates += 1
                    elif self._reason is None:
                        self._reason = "otel_trace_conflict"
                    continue
                if len(self._spans) >= MAX_SPANS:
                    self._truncated = True
                    self._reason = self._reason or "otel_payload_limit"
                    continue
                self._spans[span.identity] = span
            self.last_activity = time.monotonic()

    def close(self) -> None:
        with self._lock:
            self._closed = True

    def evidence(self) -> TraceEvidence:
        with self._lock:
            spans = sorted(self._spans.values(), key=lambda item: (item.started_at, item.span_id))
            complete = self._closed and not self._truncated and self._reason is None
            return TraceEvidence(
                schema_version=1,
                execution_id=self.execution_id,
                complete=complete,
                receiver_closed=self._closed,
                accepted=len(spans),
                rejected=self._rejected,
                duplicates=self._duplicates,
                late=self._late,
                ignored=self._ignored,
                truncated=self._truncated,
                reason=None if complete else (self._reason or "otel_receiver_open"),
                tool_spans=spans,
            )


def write_trace_evidence(path: Path, evidence: TraceEvidence) -> None:
    from gazua.runtime.evidence import write_atomic

    write_atomic(path, evidence.model_dump_json() + "\n")


def read_trace_evidence(path: Path, execution_id: str) -> TraceEvidence | None:
    """The attempt's sidecar, or None when it is missing, unreadable or names another attempt."""
    from pydantic import ValidationError

    try:
        evidence = TraceEvidence.model_validate_json(path.read_bytes())
    except (OSError, ValidationError, ValueError):
        return None
    return evidence if evidence.execution_id == execution_id else None


__all__ = ["TraceCollector", "read_trace_evidence", "write_trace_evidence"]
