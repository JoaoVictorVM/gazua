import json
from pathlib import Path
from typing import Any

from report_factory import FOUND, document, five_states, victim_order
from verdict_factory import CANARY, RUN_ID, config

from gazua.reports.builder import Excerpt, ProofItem
from gazua.reports.capture import (
    MAX_EXCERPT_BYTES,
    ReportEvidenceCollector,
)
from gazua.reports.redaction import PLACEHOLDERS, ReportRedactionPolicy, ReportRedactor
from gazua.runtime.evidence import EvidenceStore, PrivateEvidence
from gazua.runtime.run_models import ExecutionRecord
from gazua.verdicts.models import Proof

SECRET = "ghp_" + "Z" * 36


def collector(**policy: Any) -> ReportEvidenceCollector:
    chosen = ReportRedactionPolicy.from_config(config(), **policy)
    return ReportEvidenceCollector(ReportRedactor(chosen))


def test_return_snapshot_is_taken_before_private_discard(tmp_path: Path) -> None:
    capture = collector()
    store = EvidenceStore(tmp_path, tmp_path / "engine", ReportRedactor())
    store.open()
    deleted: list[str] = []

    def after_verdict(record: ExecutionRecord, private: PrivateEvidence) -> None:
        folder = store.working_directory(record.execution_id)
        capture(record, private)
        store.discard(record.execution_id)
        deleted.append(str(folder))
        assert not folder.exists()

    built = document(
        five_states(found_return=victim_order(note=CANARY, token=SECRET)),
        on_evidence=after_verdict,
        excerpts=capture,
    )

    snapshot = built.proofs[0]
    assert snapshot.attack_key == FOUND
    assert snapshot.source == "tool_return"
    assert snapshot.omission_reason is None
    assert isinstance(snapshot.content, dict)
    original = snapshot.content["original"]
    assert isinstance(original, dict)
    assert original["note"] == CANARY
    assert original["token"] == PLACEHOLDERS["sensitive"]
    assert SECRET not in built.model_dump_json()
    assert snapshot.locator["call_seq"] == 1
    assert deleted
    assert not hasattr(capture, "evidence")
    kept = vars(capture) if hasattr(capture, "__dict__") else {}
    assert not any(isinstance(value, PrivateEvidence) for value in kept.values())


def test_missing_excerpt_preserves_native_proof() -> None:
    built = document(excerpts=collector())

    snapshot = built.proofs[0]
    native = built.verdicts.results[0].proof[0]
    assert snapshot.content is None
    assert snapshot.omission_reason == "excerpt_unavailable"
    assert snapshot.locator["execution_id"] == native.execution_id
    assert snapshot.locator["reference"] == native.reference
    assert built.findings[0].proof_ids == [snapshot.id]


def test_failed_projection_is_reported_without_affecting_verdicts() -> None:
    capture = collector()

    def broken(record: ExecutionRecord, private: PrivateEvidence) -> None:
        capture(record, PrivateEvidence(**{**_fields(private), "execution_id": "GAZUA-other"}))

    built = document(on_evidence=broken, excerpts=capture)

    assert built.verdicts.results[0].state == "finding"
    assert built.proofs[0].omission_reason == "evidence_capture_failed"
    assert {item.code for item in capture.diagnostics()} == {"evidence_capture_failed"}


def _fields(private: PrivateEvidence) -> dict[str, Any]:
    return {name: getattr(private, name) for name in private.__slots__}


def _proof(seq: int) -> Proof:
    return Proof(
        signal="sensitive_tool_call",
        execution_id="GAZUA-exec-0001",
        call_seq=seq,
        facts={"tool": "refund"},
    )


def test_limits_and_proof_priority_are_deterministic(monkeypatch: Any) -> None:
    import gazua.reports.capture as module

    total = 64 * 1024
    monkeypatch.setattr(module, "MAX_SNAPSHOT_BYTES", total)
    from verdict_factory import call, context, evidence, record

    item = context("sensitive_tool_call", "tools", key="tools:permission-03:many")
    execution = record(item, execution_id="GAZUA-exec-0001")
    big = "y" * (MAX_EXCERPT_BYTES * 2)
    calls = [call(seq, "refund", arguments={"note": big}) for seq in range(1, 12)]
    capture = collector()
    capture(execution, evidence(execution, calls=calls))
    items = [
        ProofItem("tools:permission-03:many", seq - 1, _proof(seq), "call") for seq in range(1, 12)
    ]

    first = capture.excerpts(items)
    second = capture.excerpts(items)

    assert first == second
    kept = [entry for entry in first if entry.content is not None]
    omitted = [entry for entry in first if entry.content is None]
    assert all(entry.truncated for entry in kept)
    assert all(len(json.dumps(entry.content).encode()) <= MAX_EXCERPT_BYTES + 64 for entry in kept)
    assert (
        sum(len(json.dumps(entry.content, ensure_ascii=False).encode()) for entry in kept) <= total
    )
    assert omitted
    assert all(entry.omission_reason == "snapshot_limit_reached" for entry in omitted)
    assert first.index(omitted[0]) == len(kept)
    assert isinstance(first[0], Excerpt)
    assert RUN_ID.startswith("GAZUA-run-")
