"""Order, stops and exit codes of the demo, with the mode service replaced by a stand-in."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from gazua.catalog.loader import load_catalog
from gazua.config.loader import load_config
from gazua.demo import target
from gazua.demo.models import DemoOptions
from gazua.demo.runner import exit_precedence, run_demo
from gazua.demo.workspace import prepare_workspace
from gazua.integration.registry import RegisteredTool
from gazua.modes.agent import select_agent_molds
from gazua.modes.agent_models import AgentOptions
from gazua.modes.agent_plan import plan_agent
from gazua.modes.tools import tools_molds
from gazua.modes.tools_models import ToolsInventory
from gazua.modes.tools_plan import plan_tools
from gazua.reports.execution import ExecutionOutcome, ReportOutput
from gazua.runtime.tools import ToolInventory


class Lines:
    def __init__(self) -> None:
        self.out: list[str] = []
        self.err: list[str] = []

    def output(self) -> ReportOutput:
        return ReportOutput(
            say=self.out.append,
            lines=lambda lines: self.out.extend(lines),
            warn=self.err.append,
        )


def fake_service(monkeypatch: pytest.MonkeyPatch, codes: dict[str, int], calls: list[str]) -> None:
    def execute_mode(mode: str, *_: Any, **options: Any) -> ExecutionOutcome:
        calls.append(mode)
        run_id = f"GAZUA-run-2026010100000{len(calls)}-abcdef"
        document = SimpleNamespace(run_id=run_id, findings=[object()] * len(calls))
        return ExecutionOutcome(
            exit_code=codes[mode],  # type: ignore[arg-type]
            native=SimpleNamespace(engine=SimpleNamespace(interrupted=False)),
            document=document,  # type: ignore[arg-type]
            paths={"archive": f".gazua/runs/{run_id}/run.json"},
        )

    monkeypatch.setattr("gazua.reports.execution.execute_mode", execute_mode)


def demo(tmp_path: Path, **options: Any) -> tuple[Any, Lines]:
    lines = Lines()
    chosen = DemoOptions(output="demo", **{"no_open": True, **options})
    return run_demo(chosen, lines.output(), cwd=tmp_path, opener=lambda _: True), lines


def test_tools_gate_does_not_skip_agent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    fake_service(monkeypatch, {"tools": 1, "agent": 0}, calls)

    result, lines = demo(tmp_path)

    assert calls == ["tools", "agent"]
    assert result.exit_code == 1
    assert result.agent.started is True
    assert lines.out[0].startswith("This demo uses a simulated model")
    assert result.projection() == {
        "workspace": str(tmp_path / "demo"),
        "index": str(tmp_path / "demo" / "index.html"),
        "tools": {"started": True, "exit_code": 1},
        "agent": {"started": True, "exit_code": 0},
        "browser": "skipped",
        "exit_code": 1,
    }


def test_operational_error_prevents_next_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    fake_service(monkeypatch, {"tools": 2, "agent": 0}, calls)

    result, _ = demo(tmp_path)

    assert calls == ["tools"]
    assert result.exit_code == 2
    assert result.agent.started is False
    assert result.agent.reason == "previous_mode_failed"
    index = (tmp_path / "demo" / "index.html").read_text(encoding="utf-8")
    assert "Not started (previous mode failed)" in index


def test_no_report_is_never_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def execute_mode(*_: Any, **__: Any) -> ExecutionOutcome:
        return ExecutionOutcome(exit_code=0)

    monkeypatch.setattr("gazua.reports.execution.execute_mode", execute_mode)

    result, _ = demo(tmp_path)

    assert result.exit_code == 2


@pytest.mark.parametrize(
    ("codes", "expected"),
    [((0, 0), 0), ((1, 0), 1), ((0, 1), 1), ((1, 2), 2), ((2, None), 2), ((None, None), 2)],
)
def test_exit_precedence(codes: Sequence[Any], expected: int) -> None:
    assert exit_precedence(*codes) == expected


def _inventory(config: Any) -> ToolsInventory:
    registered = {
        name: (RegisteredTool(name, [function], proxy=function),)
        for name, function in {
            "get_order": target.get_order,
            "refund_order": target.refund_order,
            "send_email": target.send_email,
            "search_policy": target.search_policy,
        }.items()
    }
    document = ToolInventory.collect(config, registered).describe()
    return ToolsInventory.model_validate({**document, "complete": True})


def test_counts_fit_limits(tmp_path: Path) -> None:
    created = prepare_workspace(tmp_path / "demo")
    config = load_config(created.config_path).config
    entries = load_catalog(config, config_dir=created.root, release="v0.2").entries
    inventory = _inventory(config)
    options = AgentOptions()

    tools = plan_tools(tools_molds(entries), config, inventory, language="en")
    agent = plan_agent(
        select_agent_molds(entries, options),
        config,
        inventory,
        language="en",
        repetitions=options.effective_repetitions,
        quick=False,
        exact_mold=None,
    )

    assert options.effective_repetitions == 5
    assert len(tools_molds(entries)) == 15
    assert len(select_agent_molds(entries, options)) == 15
    assert 0 < len(tools.requests) <= config.limits.max_runs
    assert 0 < len(agent.requests) <= config.limits.max_runs
    assert len(agent.legitimate) == 2
