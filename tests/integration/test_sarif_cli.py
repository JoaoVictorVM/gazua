import json
import os
import shutil
import socket
from pathlib import Path
from typing import Any

import pytest
from ci_support import ROOT, plain_run
from typer.testing import CliRunner

from gazua.cli import app
from gazua.reports.storage import document_json

SUPPORT = ROOT / "tests" / "support"


@pytest.fixture
def offline(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("gazua sarif must not open a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def _sarif(cwd: Path, *arguments: str) -> Any:
    previous = Path.cwd()
    os.chdir(cwd)
    try:
        return CliRunner().invoke(app, ["sarif", *arguments])
    finally:
        os.chdir(previous)


@pytest.mark.usefixtures("offline")
@pytest.mark.parametrize("name", ["run-example.json", "run-example-v2.json"])
def test_sarif_reads_current_and_legacy_runs_offline(tmp_path: Path, name: str) -> None:
    shutil.copy(SUPPORT / name, tmp_path / "run.json")
    (tmp_path / "current.json").write_text(document_json(plain_run()), encoding="utf-8")

    legacy = _sarif(tmp_path, "--from", "run.json")
    current = _sarif(tmp_path, "--from", "current.json", "--output", "out/current.sarif")

    assert legacy.exit_code == 0, legacy.output
    assert current.exit_code == 0, current.output
    data = json.loads((tmp_path / ".gazua/ci/gazua.sarif").read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert (tmp_path / ".gazua/ci/.gazua-ci.json").is_file()
    assert (tmp_path / "out/current.sarif").is_file()
    assert not (tmp_path / "gazua.yaml").exists()


@pytest.mark.usefixtures("offline")
def test_gated_run_still_generates_with_zero(tmp_path: Path) -> None:
    run = plain_run()
    assert run.report_exit_code == 1
    (tmp_path / "run.json").write_text(document_json(run), encoding="utf-8")

    result = _sarif(tmp_path, "--from", "run.json", "--config-path", "app/gazua.yaml")

    assert result.exit_code == 0, result.output
    assert "Wrote 1 SARIF result from run" in result.output
    data = json.loads((tmp_path / ".gazua/ci/gazua.sarif").read_text(encoding="utf-8"))
    location = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "app/gazua.yaml"


@pytest.mark.parametrize(
    ("content", "arguments"),
    [
        ("{", ()),
        ('{"schema_version": 99}', ()),
        (None, ("--output", "../escape.sarif")),
        (None, ("--output", ".gazua")),
        (None, ("--config-path", "/etc/passwd")),
        (None, ("--from", "https://example.test/run.json")),
    ],
)
def test_invalid_run_returns_two(
    tmp_path: Path, content: str | None, arguments: tuple[str, ...]
) -> None:
    text = content if content is not None else document_json(plain_run())
    (tmp_path / "run.json").write_text(text, encoding="utf-8")
    (tmp_path / ".gazua").mkdir()

    result = _sarif(tmp_path, "--from", "run.json", *arguments)

    assert result.exit_code == 2
    assert "Traceback" not in result.output
    assert not (tmp_path.parent / "escape.sarif").exists()
    assert not (tmp_path / ".gazua/ci/gazua.sarif").exists()


def test_atomic_write_preserves_previous_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "run.json").write_text(document_json(plain_run()), encoding="utf-8")
    assert _sarif(tmp_path, "--from", "run.json").exit_code == 0
    target = tmp_path / ".gazua/ci/gazua.sarif"
    previous = target.read_bytes()
    (tmp_path / "broken.json").write_text("{", encoding="utf-8")

    invalid = _sarif(tmp_path, "--from", "broken.json")

    def failing(*args: Any, **kwargs: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", failing)
    interrupted = _sarif(tmp_path, "--from", "run.json")

    assert (invalid.exit_code, interrupted.exit_code) == (2, 2)
    assert target.read_bytes() == previous
    assert [item.name for item in target.parent.iterdir() if item.name.endswith(".tmp")] == []


def test_clean_removes_managed_ci_folder_only(tmp_path: Path) -> None:
    (tmp_path / "run.json").write_text(document_json(plain_run()), encoding="utf-8")
    assert _sarif(tmp_path, "--from", "run.json").exit_code == 0

    cleaned = _sarif_clean(tmp_path)

    assert cleaned.exit_code == 0, cleaned.output
    assert not (tmp_path / ".gazua/ci").exists()
    assert _sarif(tmp_path, "--from", "run.json").exit_code == 0
    (tmp_path / ".gazua/ci/notes.txt").write_text("mine", encoding="utf-8")
    kept = _sarif_clean(tmp_path)
    assert kept.exit_code == 0
    assert (tmp_path / ".gazua/ci/notes.txt").is_file()


def _sarif_clean(cwd: Path) -> Any:
    previous = Path.cwd()
    os.chdir(cwd)
    try:
        return CliRunner().invoke(app, ["clean"])
    finally:
        os.chdir(previous)
