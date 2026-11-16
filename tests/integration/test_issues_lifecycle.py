from pathlib import Path
from typing import Any

import pytest
from report_factory import document
from typer.testing import CliRunner
from verify_support import gazua, latest_run

from gazua.issues.export import export_issues
from gazua.issues.models import IssueOptions
from gazua.reports.lifecycle import LifecycleLock, apply_retention, managed_runs
from gazua.reports.storage import document_json


def _issues(root: Path) -> Path:
    return root / ".gazua" / "issues"


def test_clean_removes_only_managed_issue_exports(tools_project: Any) -> None:
    root = tools_project.root
    assert tools_project.cli("--tools", "--mold", "idor-01").returncode == 1
    run_id = latest_run(root)["run_id"]
    assert gazua(root, "issues").returncode == 0
    unknown = _issues(root) / "GAZUA-run-mine"
    unknown.mkdir()
    (unknown / "notes.md").write_text("mine", encoding="utf-8")
    stray = _issues(root) / "README.md"
    stray.write_text("mine too", encoding="utf-8")

    cleaned = gazua(root, "clean")

    assert cleaned.returncode == 0, cleaned.stderr
    assert "Removed 1 issue exports." in cleaned.stdout
    assert not (_issues(root) / run_id).exists()
    assert (unknown / "notes.md").read_text(encoding="utf-8") == "mine"
    assert stray.read_text(encoding="utf-8") == "mine too"


def test_run_retention_preserves_exports(tools_project: Any) -> None:
    root = tools_project.root
    assert tools_project.cli("--tools", "--mold", "idor-01").returncode == 1
    run_id = latest_run(root)["run_id"]
    assert gazua(root, "issues").returncode == 0
    exported = sorted(path.name for path in (_issues(root) / run_id).iterdir())

    with LifecycleLock(root):
        retained, diagnostics = apply_retention(root, keep=0)

    assert (retained, diagnostics) == (0, [])
    assert managed_runs(root) == []
    assert sorted(path.name for path in (_issues(root) / run_id).iterdir()) == exported


def test_busy_lock_prevents_export(tmp_path: Path) -> None:
    (tmp_path / "run.json").write_text(document_json(document()), encoding="utf-8")

    with LifecycleLock(tmp_path):
        busy = gazua(tmp_path, "issues", "--from", "run.json")

    assert busy.returncode == 2
    assert "Another Gazua command is using .gazua/" in busy.stderr
    assert not _issues(tmp_path).exists()


def test_interrupt_does_not_publish_partial_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "run.json").write_text(document_json(document()), encoding="utf-8")

    def interrupt() -> None:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        export_issues(tmp_path, IssueOptions(Path("run.json")), before_swap=interrupt)

    assert list(_issues(tmp_path).iterdir()) == []
    with LifecycleLock(tmp_path):
        pass

    from gazua import cli
    from gazua.issues import export

    def stopped(*_: Any, **__: Any) -> Any:
        raise KeyboardInterrupt

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(export, "export_issues", stopped)
    result = CliRunner().invoke(cli.app, ["issues", "--from", "run.json"])

    assert result.exit_code == 130
    assert list(_issues(tmp_path).iterdir()) == []
