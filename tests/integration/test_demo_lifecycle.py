"""Interruption, write failures, retention and reuse of the demo folder."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest
from demo_support import copy_workspace

from gazua.demo.models import DemoOptions
from gazua.demo.runner import run_demo
from gazua.reports.execution import ReportOutput
from gazua.reports.storage import StorageError


def _output(lines: list[str], on_line: Any = None) -> ReportOutput:
    def say(text: str) -> None:
        lines.append(text)
        if on_line is not None:
            on_line(text)

    return ReportOutput(say=say, lines=lambda items: lines.extend(items), warn=lines.append)


def test_interrupt_cleans_up_and_skips_agent(tmp_path: Path) -> None:
    cancel = threading.Event()
    opened: list[str] = []
    lines: list[str] = []

    def stop_after_first_execution(text: str) -> None:
        if text.startswith("["):
            cancel.set()

    result = run_demo(
        DemoOptions(output="demo"),
        _output(lines, stop_after_first_execution),
        opener=lambda uri: opened.append(uri) or True,
        cwd=tmp_path,
        cancel=cancel,
    )

    assert cancel.is_set()
    assert result.tools.exit_code == 2
    assert result.agent.started is False
    assert result.agent.reason == "interrupted"
    assert result.exit_code == 2
    assert opened == []
    assert result.tools.native.engine.interrupted is True
    archive = result.tools.archive
    assert archive is not None
    assert archive.is_file()
    leftovers = [
        item for item in (tmp_path / "demo" / ".gazua").rglob("*") if item.suffix == ".tmp"
    ]
    assert leftovers == []
    index = (tmp_path / "demo" / "index.html").read_text(encoding="utf-8")
    assert "Not started (interrupted)" in index


def test_write_failure_keeps_previous_reports(
    clean_demo: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = copy_workspace(clean_demo.workspace, tmp_path / "gazua-demo")
    gazua = workspace / ".gazua"
    before = {
        path.relative_to(workspace).as_posix(): path.read_bytes()
        for path in gazua.rglob("*")
        if path.is_file() and path.name != ".lifecycle.lock"
    }

    def fail(*_: Any, **__: Any) -> Any:
        raise StorageError("report_write_failed")

    monkeypatch.setattr("gazua.reports.storage.save_run", fail)
    lines: list[str] = []

    result = run_demo(DemoOptions(output="gazua-demo", no_open=True), _output(lines), cwd=tmp_path)

    assert result.exit_code == 2
    assert result.tools.exit_code == 2
    assert result.agent.started is False
    assert any("could not be written" in line for line in lines)
    for relative, content in before.items():
        assert (workspace / relative).read_bytes() == content, relative


def test_retention_keeps_current_pair(reused_demo: Any) -> None:
    run = reused_demo["run"]
    runs = run.workspace / ".gazua" / "runs"

    assert run.result.returncode == 1, run.result.stderr
    names = sorted(item.name for item in runs.iterdir())
    documents = run.documents()
    assert len(names) == 20
    assert {documents["tools"]["run_id"], documents["agent"]["run_id"]} <= set(names)
    seeded = [name for name in names if name.startswith("GAZUA-run-20200101")]
    assert len(seeded) == 18
    assert "GAZUA-run-20200101000000-000000" not in names


def test_clean_then_demo_recreates_reports(reused_demo: Any) -> None:
    run = reused_demo["run"]

    assert reused_demo["clean"].returncode == 0, reused_demo["clean"].stderr
    assert reused_demo["left"] == []
    for kept in (".gazua", ".gazua-demo.json", ".gitignore", "gazua.yaml", "index.html"):
        assert kept in reused_demo["after_clean"]
    assert run.result.returncode == 1
    assert sorted(run.documents()) == ["agent", "tools"]
    assert (run.workspace / ".gazua" / "report.html").is_file()
