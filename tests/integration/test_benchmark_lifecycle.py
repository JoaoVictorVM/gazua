import json
import sys
import threading
from pathlib import Path
from typing import Any

import pytest
from benchmarks.selftest import __main__ as command
from benchmarks.selftest.models import BenchmarkSummary
from benchmarks.selftest.runner import BenchmarkOptions, run_benchmark
from benchmarks.selftest.storage import StorageError, create_output

from conftest import ROOT, build_clean_environment, run_process

SELECTION = ["permission-01", "output-01"]


def options(root: Path, *molds: str) -> BenchmarkOptions:
    return BenchmarkOptions(molds=list(molds or SELECTION), output=str(root / "out"))


def test_interruption_preserves_partial_summary(tmp_path: Path) -> None:
    cancel = threading.Event()

    def say(line: str) -> None:
        if line.startswith("[2/"):
            cancel.set()

    outcome = run_benchmark(options(tmp_path), root=tmp_path, say=say, cancel=cancel)

    assert outcome.exit_code == 2
    assert outcome.summary.status == "incomplete"
    saved = BenchmarkSummary.model_validate_json((outcome.folder / "benchmark.json").read_bytes())
    outcomes = {cell.outcome for cell in saved.cells}
    assert "error" in outcomes
    assert "passed" in outcomes
    assert all("interrupted" in cell.diagnostics for cell in saved.cells if cell.outcome == "error")


def test_write_failure_is_nonzero(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    existing = tmp_path / "taken"
    existing.mkdir()
    assert command.main(["--mold", "permission-01", "--output", str(existing)], root=tmp_path) == 2
    with pytest.raises(StorageError, match="output_exists"):
        create_output(existing, tmp_path)

    def broken(folder: Path, name: str, text: str) -> Path:
        raise StorageError("write_failed")

    monkeypatch.setattr(command, "write_atomic", broken)
    code = command.main(
        ["--mold", "permission-01", "--output", str(tmp_path / "new")], root=tmp_path
    )
    assert code == 2


def test_workspace_isolation(tmp_path: Path) -> None:
    outcome = run_benchmark(options(tmp_path), root=tmp_path, say=lambda _line: None)
    runs = sorted(path.name for path in (outcome.folder / "runs").iterdir())
    assert len(runs) == len(set(runs))
    for name in runs:
        workspace = outcome.folder / "runs" / name
        profile = json.loads((workspace / "profile.json").read_text(encoding="utf-8"))
        assert (workspace / "gazua.yaml").is_file()
        assert (workspace / ".gazua" / "run.json").is_file()
        if "mutant" in name:
            assert profile["variant"] == "mutant"
    for cell in outcome.summary.cells:
        if cell.run_document is not None:
            assert cell.run_document.startswith("runs/")
            assert (outcome.folder / cell.run_document).is_file()
    # Nothing was written outside the new result folder.
    assert sorted(path.name for path in tmp_path.iterdir()) == ["out"]
    with pytest.raises(StorageError):
        run_benchmark(options(tmp_path), root=tmp_path, say=lambda _line: None)


def test_cli_matches_programmatic_result(tmp_path: Path) -> None:
    programmatic = run_benchmark(
        options(tmp_path / "a", "permission-01"), root=tmp_path, say=lambda _line: None
    )
    result = run_process(
        [
            sys.executable,
            "-m",
            "benchmarks.selftest",
            "--mold",
            "permission-01",
            "--output",
            str(tmp_path / "b"),
        ],
        cwd=ROOT,
        env=build_clean_environment(),
    )

    assert result.returncode == programmatic.exit_code == 0, result.stdout + result.stderr
    assert "This is a selection" in result.stdout
    saved = BenchmarkSummary.model_validate_json((tmp_path / "b" / "benchmark.json").read_bytes())

    def shape(summary: Any) -> list[tuple[Any, ...]]:
        return [
            (
                cell.case_id,
                cell.language,
                cell.outcome,
                cell.observed_states,
                [key.sort_key() for key in cell.observed_findings],
            )
            for cell in summary.cells
        ]

    assert shape(saved) == shape(programmatic.summary)
    assert (tmp_path / "b" / "summary.md").is_file()
    assert saved.artifacts == ["summary.md"]


def test_unknown_options_fail_before_running(tmp_path: Path) -> None:
    assert command.main(["--mold", "nope-99"], root=tmp_path) == 2
    assert command.main(["--framework", "cobol"], root=tmp_path) == 2
    assert command.main(["--release", "v9.9"], root=tmp_path) == 2
    assert command.main(["--mold", "idor-05"], root=tmp_path) == 2
    assert list(tmp_path.iterdir()) == []
