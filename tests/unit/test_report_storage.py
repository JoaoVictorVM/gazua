import json
import os
from pathlib import Path

import pytest
from report_factory import document

from gazua.reports import storage
from gazua.reports.lifecycle import managed_runs
from gazua.reports.storage import (
    JOURNAL,
    StorageError,
    publish_latest,
    recover_latest,
    write_history,
)

OLD = {"run.json": "{}\n", "report.html": "<p>old</p>", "report.md": "old\n"}
NEW = {"run.json": '{"new": 1}\n', "report.html": "<p>new</p>", "report.md": "new\n"}


def latest(root: Path) -> dict[str, str]:
    return {
        name: (root / ".gazua" / name).read_text(encoding="utf-8")
        for name in OLD
        if (root / ".gazua" / name).exists()
    }


def test_failed_latest_commit_restores_previous_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    publish_latest(tmp_path, OLD)
    real = os.replace
    moves: list[str] = []

    def failing(source: object, target: object) -> None:
        if Path(str(target)).parent.name == ".gazua" and Path(str(source)).parent.name != ".gazua":
            moves.append(str(target))
            if len(moves) == 2:
                raise OSError("disk full")
        real(source, target)  # type: ignore[arg-type]

    monkeypatch.setattr(storage.os, "replace", failing)
    with pytest.raises(StorageError) as caught:
        publish_latest(tmp_path, NEW)
    monkeypatch.setattr(storage.os, "replace", real)

    assert caught.value.code == "latest_publish_failed"
    assert latest(tmp_path) == OLD
    assert not (tmp_path / ".gazua" / JOURNAL).exists()


def test_interrupted_journal_is_recovered(tmp_path: Path) -> None:
    publish_latest(tmp_path, OLD)
    folder = tmp_path / ".gazua"
    backup = folder / storage.BACKUP
    backup.mkdir()
    for name, content in OLD.items():
        (backup / name).write_text(content, encoding="utf-8")
    (folder / "run.json").write_text(NEW["run.json"], encoding="utf-8")
    (folder / JOURNAL).write_text(json.dumps({"version": 1, "files": list(OLD)}), encoding="utf-8")

    assert recover_latest(tmp_path) is True

    assert latest(tmp_path) == OLD
    assert not (folder / JOURNAL).exists()
    assert not backup.exists()
    assert recover_latest(tmp_path) is False


def test_unknown_manifest_is_not_owned(tmp_path: Path) -> None:
    built = document()
    folder = write_history(tmp_path, built, "<p></p>", "x\n")
    assert [item.run_id for item in managed_runs(tmp_path)] == [built.run_id]
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))

    for change in (
        {"owner": "someone"},
        {"version": 2},
        {"complete": False},
        {"run_id": "GAZUA-run-other"},
        {"created_at": "yesterday"},
    ):
        (folder / "manifest.json").write_text(json.dumps({**manifest, **change}), "utf-8")
        assert managed_runs(tmp_path) == []
    (folder / "manifest.json").write_text("not json", encoding="utf-8")
    assert managed_runs(tmp_path) == []


def test_history_is_complete_before_its_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    built = document()
    real = storage.write_atomic

    def failing(path: Path, content: str) -> None:
        if path.name == "report.md":
            raise OSError("disk full")
        real(path, content)

    monkeypatch.setattr(storage, "write_atomic", failing)
    with pytest.raises(StorageError):
        storage.save_run(tmp_path, built, "<p></p>", "x\n")

    assert not (tmp_path / ".gazua" / "runs" / built.run_id / "manifest.json").exists()
    assert managed_runs(tmp_path) == []
    assert not (tmp_path / ".gazua" / "run.json").exists()
