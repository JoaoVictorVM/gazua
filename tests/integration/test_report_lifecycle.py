import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from report_factory import document
from report_support import gazua

from gazua.reports.lifecycle import LifecycleLock, LockBusy, apply_retention, managed_runs
from gazua.reports.models import RunDocument
from gazua.reports.rendering import render_report
from gazua.reports.storage import save_run, write_history

HOLD_LOCK = (
    "import sys, time\n"
    "from pathlib import Path\n"
    "from gazua.reports.lifecycle import LifecycleLock\n"
    "with LifecycleLock(Path(sys.argv[1])):\n"
    "    print('locked', flush=True)\n"
    "    sys.stdin.readline()\n"
)


def dated(number: int) -> RunDocument:
    base = document()
    run_id = f"GAZUA-run-2026010100{number:04d}-abc{number:03d}"
    metadata = base.metadata.model_copy(
        update={"created_at": f"2026-01-{1 + number // 24:02d}T{number % 24:02d}:00:00.000000Z"}
    )
    engine = base.engine.model_copy(
        update={
            "run_id": run_id,
            "records": [item.model_copy(update={"run_id": run_id}) for item in base.engine.records],
        }
    )
    return RunDocument.model_validate(
        {
            **base.model_dump(),
            "run_id": run_id,
            "metadata": metadata.model_dump(),
            "engine": engine.model_dump(),
            "verdicts": {**base.verdicts.model_dump(), "run_id": run_id},
        }
    )


def test_twenty_first_run_removes_oldest_and_clean_removes_all_owned(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    documents = [dated(number) for number in range(21)]
    # Saved out of order: retention follows the recorded dates, not the order of the writes.
    for item in [*documents[1:20], documents[0]]:
        write_history(root, item, "<html></html>", "# report\n")
    assert len(managed_runs(root)) == 20
    unknown = root / ".gazua" / "runs" / "my-notes"
    unknown.mkdir()
    (unknown / "keep.txt").write_text("mine", encoding="utf-8")
    stray = root / ".gazua" / "notes.txt"
    stray.write_text("mine", encoding="utf-8")

    html, markdown = render_report(documents[20])
    saved = save_run(root, documents[20], html, markdown)

    kept = [item.run_id for item in managed_runs(root)]
    assert saved.retained_runs == 20
    assert documents[0].run_id not in kept
    assert kept == [item.run_id for item in documents[1:]]
    assert not (root / ".gazua" / "runs" / documents[0].run_id).exists()
    assert (root / ".gazua" / "report.html").read_text(encoding="utf-8") == html
    assert json.loads((root / ".gazua" / "run.json").read_text("utf-8"))["run_id"] == (
        documents[20].run_id
    )

    cleaned = gazua(root, "clean")
    again = gazua(root, "clean")

    assert cleaned.returncode == 0, cleaned.stderr
    assert "Removed 20 runs and 3 report files." in cleaned.stdout
    assert again.returncode == 0
    assert "Removed 0 runs and 0 report files." in again.stdout
    assert (unknown / "keep.txt").exists()
    assert stray.exists()
    assert (root / ".gazua").is_dir()
    assert managed_runs(root) == []
    empty = tmp_path / "empty"
    empty.mkdir()
    assert "Removed 0 runs" in gazua(empty, "clean").stdout
    assert not (empty / ".gazua").exists()


def _junction(link: Path, target: Path) -> bool:
    try:
        if os.name == "nt":
            import _winapi

            _winapi.CreateJunction(str(target), str(link))  # type: ignore[attr-defined]
        else:
            link.symlink_to(target, target_is_directory=True)
    except (OSError, AttributeError):
        return False
    return True


def test_clean_and_retention_refuse_active_run_and_links(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    write_history(root, dated(1), "<html></html>", "# r\n")
    holder = subprocess.Popen(
        [sys.executable, "-c", HOLD_LOCK, str(root)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout is not None
        assert holder.stdout.readline().strip() == "locked"
        busy = gazua(root, "clean")
        with pytest.raises(LockBusy), LifecycleLock(root):
            pass
    finally:
        assert holder.stdin is not None
        holder.stdin.write("\n")
        holder.stdin.flush()
        holder.wait(timeout=30)
    assert busy.returncode == 2
    assert "Another Gazua command" in busy.stderr
    assert len(managed_runs(root)) == 1

    outside = tmp_path / "outside"
    outside.mkdir()
    precious = outside / "precious.txt"
    precious.write_text("keep", encoding="utf-8")
    runs = root / ".gazua" / "runs"
    if not _junction(runs / "GAZUA-run-20260101000000-linked", outside):
        pytest.skip("links need privileges here")
    (outside / "manifest.json").write_text(
        json.dumps(
            {
                "owner": "gazua",
                "version": 1,
                "run_id": "GAZUA-run-20260101000000-linked",
                "created_at": "2025-01-01T00:00:00Z",
                "complete": True,
            }
        ),
        encoding="utf-8",
    )
    inner = runs / dated(1).run_id / "engine-link"
    linked_inside = _junction(inner, outside)

    assert apply_retention(root, keep=0)[0] >= 0
    result = gazua(root, "clean")

    assert precious.exists()
    assert (outside / "manifest.json").exists()
    if linked_inside:
        assert result.returncode == 2
        assert dated(1).run_id in result.stderr
        assert (runs / dated(1).run_id).exists()
