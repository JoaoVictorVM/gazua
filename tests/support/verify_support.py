"""Command line helpers shared by the baseline and verification integration tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from conftest import run_process


def gazua(root: Path, *arguments: str) -> Any:
    return run_process([sys.executable, "-m", "gazua", *arguments], cwd=root)


def baseline_document(root: Path) -> dict[str, Any]:
    return json.loads((root / "gazua-baseline.json").read_text(encoding="utf-8"))


def latest_run(root: Path) -> dict[str, Any]:
    return json.loads((root / ".gazua" / "run.json").read_text(encoding="utf-8"))


def accepted(root: Path, *run: str) -> dict[str, Any]:
    """Runs once, accepts the findings and returns the single baseline entry."""
    first = gazua(root, "run", *run)
    assert first.returncode == 1, first.stdout + first.stderr
    created = gazua(root, "baseline")
    assert created.returncode == 0, created.stderr
    [entry] = baseline_document(root)["entries"]
    return entry


def quiet() -> Any:
    from gazua.reports.execution import ReportOutput

    lines: list[str] = []
    return ReportOutput(
        say=lines.append, lines=lambda items: lines.extend(items), warn=lines.append
    )


def verify_in_process(
    root: Path,
    selector: str = "idor-01",
    *,
    mode: str = "tools",
    output: Any = None,
    overrides: dict[str, Any] | None = None,
    **options: Any,
) -> Any:
    """Runs a verification the way the command does, with hooks only tests can reach."""
    from gazua.baseline.plan import build_plan
    from gazua.baseline.selection import resolve
    from gazua.baseline.storage import read_baseline
    from gazua.baseline.verification import run_verification
    from gazua.catalog.loader import load_catalog
    from gazua.config.loader import load_config
    from gazua.modes.tools import discover_tools
    from gazua.reports.lifecycle import LifecycleLock
    from gazua.runtime.run_models import LimitOverrides

    config = load_config(root / "gazua.yaml").config
    catalog = load_catalog(config, config_dir=root, release="v0.2")
    loaded = read_baseline(root / "gazua-baseline.json")
    selection = resolve(selector, loaded.document, config, catalog.entries, mode)  # type: ignore[arg-type]
    plan = build_plan(selection, config, discover_tools(config, root))
    with LifecycleLock(root):
        return run_verification(
            plan,
            config,
            LimitOverrides.model_validate(overrides or {}),
            root,
            loaded,
            output or quiet(),
            locked=True,
            config_path="gazua.yaml",
            gazua_version=None,
            **options,
        )
