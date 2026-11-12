"""Treated excerpts of each execution's evidence, taken before the private copy is deleted.

The collector runs in the same ``on_evidence`` callback as the verdict collector, after it.
It keeps only treated JSON, already cut to the excerpt limit, keyed by execution, call
sequence and hit, never the private evidence object. Failing to project an execution never
affects the verdict or the deletion of the private folder; its proofs keep their native locator
and say that the excerpt is missing.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Final

from pydantic import JsonValue

from gazua.reports.builder import Excerpt, ProofItem
from gazua.reports.models import ReportDiagnostic
from gazua.reports.redaction import ReportRedactor
from gazua.runtime.evidence import PrivateEvidence
from gazua.runtime.run_models import ExecutionRecord

MAX_EXCERPT_BYTES: Final = 16 * 1024
MAX_SNAPSHOT_BYTES: Final = 8 * 1024 * 1024


def _size(value: JsonValue) -> int:
    return len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8"))


def limited(value: JsonValue, limit: int = MAX_EXCERPT_BYTES) -> tuple[JsonValue, bool]:
    """The treated value, or its JSON text cut at a character boundary when it is too large.

    Values are treated in full before this runs, so a cut never splits a secret that the
    detector could still have recognized.
    """
    text = json.dumps(value, ensure_ascii=False, allow_nan=False)
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return value, False
    return encoded[:limit].decode("utf-8", errors="ignore"), True


@dataclass(frozen=True, slots=True)
class _Kept:
    content: JsonValue
    truncated: bool


@dataclass(slots=True)
class ReportEvidenceCollector:
    """Treated projections of evidence, for the report's proof snapshots."""

    redactor: ReportRedactor
    _calls: dict[tuple[str, int], _Kept] = field(default_factory=dict[tuple[str, int], _Kept])
    _returns: dict[tuple[str, int], _Kept] = field(default_factory=dict[tuple[str, int], _Kept])
    _outputs: dict[str, _Kept] = field(default_factory=dict[str, _Kept])
    _hits: dict[tuple[str, str], _Kept] = field(default_factory=dict[tuple[str, str], _Kept])
    _failed: set[str] = field(default_factory=set[str])
    _diagnostics: list[ReportDiagnostic] = field(default_factory=list[ReportDiagnostic])
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __call__(self, record: ExecutionRecord, evidence: PrivateEvidence) -> None:
        self.on_evidence(record, evidence)

    def on_evidence(self, record: ExecutionRecord, evidence: PrivateEvidence) -> None:
        try:
            self._project(record, evidence)
        # Projection reads data from the target; its failure only loses this excerpt.
        except Exception:  # noqa: BLE001
            with self._lock:
                self._failed.add(record.execution_id)
                diagnostic = ReportDiagnostic(code="evidence_capture_failed", level="warning")
                if diagnostic not in self._diagnostics:
                    self._diagnostics.append(diagnostic)

    def diagnostics(self) -> list[ReportDiagnostic]:
        with self._lock:
            return list(self._diagnostics)

    def _keep(self, value: object, field: str) -> _Kept:
        content, truncated = limited(self.redactor.data(value, field))
        return _Kept(content, truncated)

    def _project(self, record: ExecutionRecord, evidence: PrivateEvidence) -> None:
        execution = record.execution_id
        if evidence.execution_id != execution:
            raise ValueError("correlation")
        calls = {
            (execution, call.seq): self._keep(
                call.model_dump(
                    mode="json",
                    include={
                        "seq",
                        "tool",
                        "arguments",
                        "truncated",
                        "actor",
                        "dry_run",
                        "outcome",
                        "low_fidelity",
                        "result_type",
                        "block_reason",
                    },
                ),
                "evidence.call",
            )
            for call in evidence.calls
        }
        returns: dict[tuple[str, int], _Kept] = {}
        channel = evidence.returns
        if channel is not None and channel.valid:
            for seq, observation in channel.returns.items():
                if observation.unavailable_reason is not None:
                    continue
                returns[(execution, seq)] = self._keep(
                    {"original": observation.original, "delivered": observation.delivered},
                    "evidence.tool_return",
                )
        hits = {
            (execution, item.record.hit_id): self._keep(
                {
                    "method": item.record.method,
                    "logical_url": item.record.logical_url,
                    "content_type": item.content_type,
                    "body": item.body.decode("utf-8", errors="replace"),
                    "truncated": item.record.truncated,
                },
                "evidence.receiver",
            )
            for item in evidence.receiver_hits
        }
        output = None if evidence.output is None else self._keep(evidence.output, "evidence.output")
        with self._lock:
            self._calls.update(calls)
            self._returns.update(returns)
            self._hits.update(hits)
            if output is not None:
                self._outputs[execution] = output

    def _find(self, item: ProofItem) -> _Kept | None:
        proof = item.proof
        execution = proof.execution_id
        if item.source == "call" and proof.call_seq is not None:
            return self._calls.get((execution, proof.call_seq))
        if item.source == "tool_return" and proof.call_seq is not None:
            return self._returns.get((execution, proof.call_seq))
        if item.source == "receiver" and proof.hit_id is not None:
            return self._hits.get((execution, proof.hit_id))
        if item.source in ("output", "sink", "memory"):
            return self._outputs.get(execution)
        if item.source == "operational":
            return _Kept(dict(proof.facts), False)
        return None

    def excerpts(self, items: Sequence[ProofItem]) -> list[Excerpt]:
        """One excerpt per proof, in the given order, within the run's total limit.

        Proofs come first and in a fixed order, so the same run always keeps the same
        excerpts; once the limit is reached the rest say so instead of disappearing.
        """
        used = 0
        found: list[Excerpt] = []
        with self._lock:
            for item in items:
                kept = self._find(item)
                if kept is None:
                    reason = (
                        "evidence_capture_failed"
                        if item.proof.execution_id in self._failed
                        else "excerpt_unavailable"
                    )
                    found.append(Excerpt(None, omission_reason=reason))
                    continue
                size = _size(kept.content)
                if used + size > MAX_SNAPSHOT_BYTES:
                    found.append(Excerpt(None, omission_reason="snapshot_limit_reached"))
                    continue
                used += size
                found.append(Excerpt(kept.content, truncated=kept.truncated))
        return found
