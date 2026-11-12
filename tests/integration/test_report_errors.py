from typing import Any

import pytest

from gazua.reports.capture import ReportEvidenceCollector
from gazua.reports.redaction import ReportRedactor
from gazua.runtime.evidence import EvidenceStore


def test_midrun_disk_error_preserves_collector_and_partial_summary(
    tools_project: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    tools_project.write(target={"reset": "tools_target:reset"})
    original = EvidenceStore.persist
    calls: list[str] = []

    def failing(self: EvidenceStore, evidence: Any, raw: Any) -> Any:
        calls.append(evidence.execution_id)
        if len(calls) == 1:
            raise OSError(28, "No space left on device")
        return original(self, evidence, raw)

    monkeypatch.setattr(EvidenceStore, "persist", failing)
    capture = ReportEvidenceCollector(ReportRedactor())

    result = tools_project.run(
        molds=("idor-01", "permission-03", "secret-01"),
        overrides={"concurrency": 1},
        on_evidence=capture,
    )

    assert calls == [result.engine.records[0].execution_id]
    first = result.engine.records[0]
    assert first.status == "completed"
    assert first.call_log is None
    by_key = {item.attack_key: item for item in result.verdicts.results}
    first_result = next(
        item
        for item in result.verdicts.results
        if any(slot.request_key == first.request_key for slot in _context(result, item).requests)
    )
    assert first_result.state == "finding"
    pending = [record for record in result.engine.records[1:] if record.status == "not_tested"]
    assert pending
    assert all(record.reason == "report_storage_unavailable" for record in pending)
    assert all(record.started_at is None for record in pending)
    assert "report_storage_unavailable" in result.engine.operational_errors
    assert result.engine.cleanup == "succeeded"
    assert result.exit_code == 2
    assert any(item.state == "not_tested" for item in by_key.values())
    assert any(effect["kind"] == "reset" for effect in tools_project.effects())


def _context(result: Any, item: Any) -> Any:
    return next(context for context in result.contexts if context.attack_key == item.attack_key)
