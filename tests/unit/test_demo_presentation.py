"""The demo page links each mode's own archive, and the browser never decides the gate."""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from gazua.demo import SIMULATION_NOTICE
from gazua.demo.models import DemoOptions, ModeOutcome
from gazua.demo.presentation import open_index, render_index
from gazua.demo.runner import run_demo
from gazua.reports.execution import ExecutionOutcome, ReportOutput


def outcome(root: Path, mode: str, run_id: str, findings: int = 2) -> ModeOutcome:
    folder = root / ".gazua" / "runs" / run_id
    return ModeOutcome(
        mode=mode,  # type: ignore[arg-type]
        started=True,
        exit_code=1,
        run_id=run_id,
        archive=folder / "run.json",
        reports={
            "html": folder / "report.html",
            "markdown": folder / "report.md",
            "json": folder / "run.json",
        },
        findings=findings,
    )


def test_index_links_distinct_archives(tmp_path: Path) -> None:
    tools = outcome(tmp_path, "tools", "GAZUA-run-1-aaaaaa")
    agent = outcome(tmp_path, "agent", "GAZUA-run-2-bbbbbb")

    page = render_index(tmp_path, tools, agent, "en")

    links = re.findall(r'href="([^"]+)"', page)
    assert links == [
        ".gazua/runs/GAZUA-run-1-aaaaaa/report.html",
        ".gazua/runs/GAZUA-run-1-aaaaaa/report.md",
        ".gazua/runs/GAZUA-run-1-aaaaaa/run.json",
        ".gazua/runs/GAZUA-run-2-bbbbbb/report.html",
        ".gazua/runs/GAZUA-run-2-bbbbbb/report.md",
        ".gazua/runs/GAZUA-run-2-bbbbbb/run.json",
    ]
    assert ".gazua/report.html" not in page
    assert SIMULATION_NOTICE["en"] in page
    assert "default-src 'none'" in page
    assert not re.search(r"(src|href)=\"(https?:)?//", page)
    assert "<script" not in page


def test_index_in_portuguese_and_for_a_mode_not_started(tmp_path: Path) -> None:
    tools = outcome(tmp_path, "tools", "GAZUA-run-1-aaaaaa")
    agent = ModeOutcome(mode="agent", started=False, exit_code=None, reason="interrupted")

    page = render_index(tmp_path, tools, agent, "pt")

    assert SIMULATION_NOTICE["pt"] in page
    assert "Não iniciado (interrupted)" in page
    assert page.count("<li>") == 3


def _service(monkeypatch: pytest.MonkeyPatch) -> None:
    def execute_mode(mode: str, *_: Any, **__: Any) -> ExecutionOutcome:
        run_id = f"GAZUA-run-{mode}-abcdef"
        return ExecutionOutcome(
            exit_code=1,
            native=SimpleNamespace(engine=SimpleNamespace(interrupted=False)),
            document=SimpleNamespace(run_id=run_id, findings=[1]),  # type: ignore[arg-type]
            paths={"archive": f".gazua/runs/{run_id}/run.json"},
        )

    monkeypatch.setattr("gazua.reports.execution.execute_mode", execute_mode)


def _output(errors: list[str]) -> ReportOutput:
    return ReportOutput(say=lambda _: None, lines=lambda _: None, warn=errors.append)


def test_browser_failure_preserves_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _service(monkeypatch)
    errors: list[str] = []

    def broken(uri: str) -> bool:
        raise RuntimeError("no display")

    result = run_demo(DemoOptions(output="demo"), _output(errors), opener=broken, cwd=tmp_path)

    assert result.browser == "failed"
    assert result.exit_code == 1
    assert any("Could not open a browser" in line for line in errors)
    assert open_index(tmp_path / "demo" / "index.html", lambda _: False) == "failed"


def test_browser_opens_the_local_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _service(monkeypatch)
    opened: list[str] = []

    result = run_demo(
        DemoOptions(output="demo"),
        _output([]),
        opener=lambda uri: opened.append(uri) or True,
        cwd=tmp_path,
    )

    assert result.browser == "opened"
    assert opened == [(tmp_path / "demo" / "index.html").resolve().as_uri()]
    assert opened[0].startswith("file://")


def test_no_open_never_launches_browser(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _service(monkeypatch)
    opened: list[str] = []
    monkeypatch.setattr("webbrowser.open", lambda *args, **kwargs: opened.append("system"))

    result = run_demo(
        DemoOptions(output="demo", no_open=True),
        _output([]),
        opener=lambda uri: opened.append(uri) or True,
        cwd=tmp_path,
    )

    assert result.browser == "skipped"
    assert opened == []
    assert result.exit_code == 1
