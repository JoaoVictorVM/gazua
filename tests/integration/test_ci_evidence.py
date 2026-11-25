import os
from pathlib import Path
from typing import Any

import pytest
from action_support import run_action

from gazua.ci.action import finish_step


def _files(folder: Path) -> list[str]:
    return sorted(
        item.relative_to(folder).as_posix() for item in folder.rglob("*") if item.is_file()
    )


def test_default_upload_set_has_no_evidence(tools_project: Any) -> None:
    outcome, outputs = run_action(tools_project.root, GAZUA_CI_MOLD="idor-01")

    assert "evidence" not in outputs.values
    assert "evidence" not in outcome.paths
    assert not (tools_project.root / ".gazua/ci/evidence").exists()


def test_opt_in_stages_only_managed_run_files(tools_project: Any) -> None:
    (tools_project.root / ".env").write_text("OPENAI_API_KEY=sk-not-real\n", encoding="utf-8")
    (tools_project.root / ".git").mkdir()
    (tools_project.root / ".git" / "config").write_text("[core]\n", encoding="utf-8")

    outcome, outputs = run_action(
        tools_project.root, GAZUA_CI_MOLD="idor-01", GAZUA_CI_UPLOAD_EVIDENCE="true"
    )

    staged = tools_project.root / outputs.values["evidence"]
    run_id = staged.name
    assert outputs.values["evidence"] == f".gazua/ci/evidence/{run_id}"
    assert outputs.values["evidence-name"] == f"gazua-evidence-{run_id}"
    files = _files(staged)
    assert {"run.json", "report.html", "report.md", "history/manifest.json"} <= set(files)
    assert all(
        name in ("run.json", "report.html", "report.md") or name.startswith("history/")
        for name in files
    )
    assert not any("private" in name for name in files)
    assert outcome.exit_code == 1


def test_glob_cannot_capture_env_or_git(tools_project: Any) -> None:
    (tools_project.root / ".env").write_text("TOKEN=x\n", encoding="utf-8")
    (tools_project.root / "gazua-baseline.json.bak").write_text("{}", encoding="utf-8")

    _, outputs = run_action(
        tools_project.root, GAZUA_CI_MOLD="idor-01", GAZUA_CI_UPLOAD_EVIDENCE="true"
    )

    files = _files(tools_project.root / outputs.values["evidence"])
    assert not any(
        name.endswith((".env", "gazua.yaml", ".bak")) or ".git" in name for name in files
    )


def test_failed_requested_upload_returns_two(tools_project: Any, capsys: Any) -> None:
    for outcome in ("failure", "skipped", ""):
        assert (
            finish_step(
                {
                    "GAZUA_CI_EXIT_CODE": "0",
                    "GAZUA_CI_UPLOAD_EVIDENCE": "true",
                    "GAZUA_CI_EVIDENCE_OUTCOME": outcome,
                }
            )
            == 2
        )
    assert "ci_evidence_upload_failed" in capsys.readouterr().out
    assert (
        finish_step(
            {
                "GAZUA_CI_EXIT_CODE": "0",
                "GAZUA_CI_UPLOAD_EVIDENCE": "true",
                "GAZUA_CI_EVIDENCE_OUTCOME": "success",
            }
        )
        == 0
    )


def test_link_in_run_folder_is_not_staged(tools_project: Any) -> None:
    first, _ = run_action(tools_project.root, GAZUA_CI_MOLD="idor-01")
    assert first.exit_code == 1
    history = next((tools_project.root / ".gazua" / "runs").iterdir())
    try:
        os.symlink(tools_project.root / "gazua.yaml", history / "leak.yaml")
    except OSError:
        pytest.skip("symbolic links are not available")

    from gazua.ci.action import stage_evidence
    from gazua.ci.storage import CiStorageError

    with pytest.raises(CiStorageError):
        stage_evidence(tools_project.root, history.name)
