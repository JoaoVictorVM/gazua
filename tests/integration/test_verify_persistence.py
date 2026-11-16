import threading
from typing import Any

import pytest
from verify_support import accepted, latest_run, verify_in_process

from gazua.reports.execution import ReportOutput


def baseline_bytes(project: Any) -> bytes:
    return (project.root / "gazua-baseline.json").read_bytes()


def test_report_failure_never_closes(tools_project: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    from gazua.reports import storage

    accepted(tools_project.root, "--tools", "--mold", "idor-01")
    before = baseline_bytes(tools_project)
    tools_project.harden()

    def refuse(*_: Any, **__: Any) -> Any:
        raise storage.StorageError("report_write_failed")

    monkeypatch.setattr(storage, "save_run", refuse)
    outcome = verify_in_process(tools_project.root)

    assert outcome.exit_code == 2
    assert outcome.persisted is False
    assert outcome.result.outcome == "verified"
    assert baseline_bytes(tools_project) == before


def test_baseline_commit_failure_keeps_evidence_and_old_state(tools_project: Any) -> None:
    accepted(tools_project.root, "--tools", "--mold", "idor-01")
    before = baseline_bytes(tools_project)
    tools_project.harden()

    def fail() -> None:
        raise OSError("disk full")

    outcome = verify_in_process(tools_project.root, before_replace=fail)

    assert outcome.exit_code == 2
    assert (outcome.persisted, outcome.error) == (False, "baseline_write_failed")
    assert baseline_bytes(tools_project) == before
    run = latest_run(tools_project.root)
    assert run["verification"]["outcome"] == "verified"
    assert run["verification"]["closure_eligible"] is True
    assert sorted(path.name for path in tools_project.root.glob("*.tmp")) == []
    assert not list(tools_project.root.glob(".gazua-baseline.json.*"))


def test_interrupt_keeps_baseline_bytes(tools_project: Any) -> None:
    accepted(tools_project.root, "--tools", "--mold", "idor-01")
    before = baseline_bytes(tools_project)
    cancel = threading.Event()
    seen: list[str] = []

    def say(text: str) -> None:
        seen.append(text)
        if len(seen) >= 3:
            cancel.set()

    output = ReportOutput(say=say, lines=lambda items: seen.extend(items), warn=seen.append)
    outcome = verify_in_process(
        tools_project.root, output=output, cancel=cancel, overrides={"concurrency": 1}
    )

    assert outcome.exit_code == 2
    assert outcome.result.outcome == "interrupted"
    assert outcome.result.proposed_status is None
    assert any(item.successes for item in outcome.result.samples)
    assert baseline_bytes(tools_project) == before
    assert latest_run(tools_project.root)["verification"]["interrupted"] is True
