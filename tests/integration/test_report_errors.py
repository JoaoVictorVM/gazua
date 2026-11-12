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


def test_unwritable_root_prints_complete_summary_and_exits_two(tmp_path: Any) -> None:
    from report_support import echo_project, gazua

    project = echo_project(tmp_path / "project")
    (project / ".gazua").write_text("a file where the folder should be", encoding="utf-8")

    result = gazua(project, "run", "--tools")

    assert result.returncode == 2
    assert "Cannot write to .gazua/" in result.stderr
    assert "| Damage |" in result.stdout
    assert "report storage unavailable" in result.stdout
    assert "Gate: no finding at a gated severity." in result.stdout
    assert "Reports:" not in result.stdout
    assert not (project / "effects").exists()
    assert (project / ".gazua").is_file()


def test_gitignore_warning_on_each_run(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    import shutil
    import subprocess

    from report_support import echo_project, gazua

    from gazua.reports import lifecycle

    warning = ".gazua/ is not in this project's .gitignore"
    project = echo_project(tmp_path / "project")
    (project / ".gitignore").unlink()
    for _ in range(2):
        result = gazua(project, "run", "--tools", "--mold", "idor-01")
        assert result.returncode == 1, result.stderr
        assert warning in result.stderr
    assert not (project / ".gitignore").exists()

    (project / ".gitignore").write_text("*.pyc\n.gazua/\n", encoding="utf-8")
    covered = gazua(project, "run", "--tools", "--mold", "idor-01")
    assert warning not in covered.stderr
    assert (project / ".gitignore").read_text(encoding="utf-8") == "*.pyc\n.gazua/\n"

    git = shutil.which("git")
    if git is not None:
        repository = echo_project(tmp_path / "repository")
        (repository / ".gitignore").unlink()
        subprocess.run([git, "init", "-q", str(repository)], check=True)
        exclude = repository / ".git" / "info" / "exclude"
        exclude.parent.mkdir(parents=True, exist_ok=True)
        exclude.write_text(".gazua/\n", encoding="utf-8")
        assert lifecycle.gitignore_covers(repository) is False
        (repository / ".gitignore").write_text("/.gazua/\n", encoding="utf-8")
        assert lifecycle.gitignore_covers(repository) is True

    monkeypatch.setattr(lifecycle.shutil, "which", lambda name: None)
    assert lifecycle.gitignore_covers(project) is True
    (project / ".gitignore").write_text("*.pyc\n", encoding="utf-8")
    assert lifecycle.gitignore_covers(project) is False
    (project / ".gitignore").write_text("**/.gazua/**\n", encoding="utf-8")
    assert lifecycle.gitignore_covers(project) is False
