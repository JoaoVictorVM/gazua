import json
import os
import subprocess
from pathlib import Path

import pytest
from report_factory import document

from gazua.issues.export import export_issues
from gazua.issues.models import IssueExportError, IssueOptions
from gazua.issues.storage import recover_exports
from gazua.reports.storage import document_json

BUILT = document()
RUN_ID = BUILT.run_id
[FINDING] = BUILT.findings
NAME = f"{FINDING.id}.md"


def _project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / ".gazua").mkdir(parents=True)
    (root / ".gazua" / "run.json").write_text(document_json(BUILT), encoding="utf-8")
    return root


def _export(root: Path, **options: bool) -> object:
    return export_issues(root, IssueOptions(Path(".gazua/run.json"), **options))


def _folder(root: Path) -> Path:
    return root / ".gazua" / "issues" / RUN_ID


def _snapshot(folder: Path) -> dict[str, bytes]:
    return {path.name: path.read_bytes() for path in sorted(folder.iterdir())}


def _link_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        if os.name != "nt":
            raise
        made = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True,
            check=False,
        )
        if made.returncode != 0:
            pytest.skip("links and junctions are unavailable here")


def test_identical_export_is_noop(tmp_path: Path) -> None:
    root = _project(tmp_path)

    first = _export(root)
    before = _snapshot(_folder(root))
    times = {path.name: path.stat().st_mtime_ns for path in _folder(root).iterdir()}
    again = _export(root)

    assert first.status == "written"  # type: ignore[attr-defined]
    assert first.files == (f".gazua/issues/{RUN_ID}/{NAME}",)  # type: ignore[attr-defined]
    assert again.status == "unchanged"  # type: ignore[attr-defined]
    assert _snapshot(_folder(root)) == before
    assert {path.name: path.stat().st_mtime_ns for path in _folder(root).iterdir()} == times
    manifest = json.loads(before["manifest.json"])
    assert manifest["owner"] == "gazua-issues"
    assert manifest["run_id"] == RUN_ID
    assert [item["name"] for item in manifest["files"]] == [NAME]
    assert "created_at" not in manifest
    assert str(root) not in before["manifest.json"].decode()


def test_conflict_requires_overwrite(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _export(root)
    issue = _folder(root) / NAME
    issue.write_text("my own notes\n", encoding="utf-8")

    with pytest.raises(IssueExportError) as edited:
        _export(root)
    assert edited.value.code == "issues_conflict"
    assert issue.read_text(encoding="utf-8") == "my own notes\n"

    with pytest.raises(IssueExportError) as option:
        _export(root, include_attack=True)
    assert option.value.code == "issues_conflict"

    replaced = _export(root, overwrite=True)
    assert replaced.status == "written"  # type: ignore[attr-defined]
    assert issue.read_text(encoding="utf-8").startswith("# High")
    assert not [path for path in (root / ".gazua" / "issues").iterdir() if path.name != RUN_ID]


def test_overwrite_preserves_unknown_files(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _export(root)
    extra = _folder(root) / "notes.txt"
    extra.write_text("keep me", encoding="utf-8")
    unknown = root / ".gazua" / "issues" / "GAZUA-run-other"
    unknown.mkdir()
    (unknown / "mine.md").write_text("mine", encoding="utf-8")

    with pytest.raises(IssueExportError) as caught:
        _export(root, overwrite=True)

    assert caught.value.code == "issues_unmanaged_destination"
    assert extra.read_text(encoding="utf-8") == "keep me"
    assert (_folder(root) / NAME).is_file()
    assert (unknown / "mine.md").read_text(encoding="utf-8") == "mine"
    extra.unlink()
    (_folder(root) / "manifest.json").unlink()
    with pytest.raises(IssueExportError) as unmanaged:
        _export(root, overwrite=True)
    assert unmanaged.value.code == "issues_unmanaged_destination"
    assert (_folder(root) / NAME).is_file()


def test_symlink_and_junction_are_refused(tmp_path: Path) -> None:
    root = _project(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    _link_or_skip(root / ".gazua" / "issues", outside)

    with pytest.raises(IssueExportError) as caught:
        _export(root)

    assert caught.value.code == "issues_path_refused"
    assert list(outside.iterdir()) == []
    link = root / ".gazua" / "issues"
    if link.is_symlink():
        link.unlink()
    else:
        os.rmdir(link)
    link.mkdir()
    _link_or_skip(_folder(root), outside)
    with pytest.raises(IssueExportError) as inner:
        _export(root)
    assert inner.value.code == "issues_path_refused"
    assert list(outside.iterdir()) == []


def test_failed_publication_recovers_previous_set(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _export(root)
    before = _snapshot(_folder(root))

    def fail() -> None:
        raise OSError("disk full")

    with pytest.raises(IssueExportError) as caught:
        export_issues(
            root,
            IssueOptions(Path(".gazua/run.json"), include_attack=True, overwrite=True),
            before_swap=fail,
        )

    assert caught.value.code == "issues_write_failed"
    assert _snapshot(_folder(root)) == before
    assert sorted(path.name for path in (root / ".gazua" / "issues").iterdir()) == [RUN_ID]

    def interrupt() -> None:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        export_issues(
            root,
            IssueOptions(Path(".gazua/run.json"), include_attack=True, overwrite=True),
            before_swap=interrupt,
        )
    assert _snapshot(_folder(root)) == before


def test_interrupted_swap_is_rolled_back_by_next_command(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _export(root)
    before = _snapshot(_folder(root))
    managed = root / ".gazua" / "issues"
    os.replace(_folder(root), managed / f".backup-{RUN_ID}")
    (managed / f".journal-{RUN_ID}.json").write_text(
        json.dumps({"version": 1, "previous": True}), encoding="utf-8"
    )

    assert recover_exports(root) == 1
    assert _snapshot(_folder(root)) == before
    assert sorted(path.name for path in managed.iterdir()) == [RUN_ID]


def test_corrupt_manifest_cannot_delete_external_path(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _export(root)
    victim = tmp_path / "outside.txt"
    victim.write_text("precious", encoding="utf-8")
    manifest_path = _folder(root) / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"].append({"name": "../../../outside.txt", "sha256": "0" * 64})
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    for overwrite in (False, True):
        with pytest.raises(IssueExportError) as caught:
            _export(root, overwrite=overwrite)
        assert caught.value.code == "issues_unmanaged_destination"
    managed = root / ".gazua" / "issues"
    (managed / f".journal-{RUN_ID}.json").write_text(
        json.dumps({"version": 1, "previous": False, "files": ["../../../outside.txt"]}),
        encoding="utf-8",
    )
    recover_exports(root)

    assert victim.read_text(encoding="utf-8") == "precious"
    assert (_folder(root) / NAME).is_file()
