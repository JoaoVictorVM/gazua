"""Runs the Action's steps in process against a real tools project, without GitHub."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ci_support import environment

from conftest import build_clean_environment, run_process
from gazua.ci.action import Outputs, RunOutcome, run_step


@dataclass
class Spy:
    """An executor that records what the target's process would receive and runs nothing."""

    calls: list[tuple[list[str], Path, dict[str, str]]] = field(
        default_factory=list[tuple[list[str], Path, dict[str, str]]]
    )

    def __call__(self, argv: Sequence[str], cwd: Path, env: dict[str, str]) -> int:
        self.calls.append((list(argv), cwd, dict(env)))
        return 0


def action_environment(root: Path, event: str = "pull_request", **extra: str) -> dict[str, str]:
    values = {**build_clean_environment(), **environment(root, event=event)}
    values["GITHUB_OUTPUT"] = str(root / "github-output.txt")
    values["GITHUB_STEP_SUMMARY"] = str(root / "step-summary.md")
    values.update(extra)
    return values


def run_action(root: Path, executor: Any = None, **extra: str) -> tuple[RunOutcome, Outputs]:
    outputs = Outputs(None)
    values = action_environment(root, **extra)
    if executor is None:
        return run_step(values, outputs=outputs), outputs
    return run_step(values, executor, outputs), outputs


def accept_findings(root: Path, mold: str = "idor-01") -> None:
    command = [sys.executable, "-m", "gazua"]
    first = run_process([*command, "run", "--tools", "--mold", mold], cwd=root)
    assert first.returncode == 1, first.stderr
    created = run_process([*command, "baseline"], cwd=root)
    assert created.returncode == 0, created.stderr
