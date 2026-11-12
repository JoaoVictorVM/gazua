"""Helpers shared by the report integration tests: projects, CLI calls and file reads."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Any

from conftest import ROOT, build_clean_environment, run_process

ECHO_CONFIG: dict[str, Any] = {
    "schema_version": 1,
    "entrypoint": "echo_target:entrypoint",
    "tools": {
        "get_order": {
            "safe": True,
            "sensitive": False,
            "owner_arg": "user_id",
            "actor_arg": "actor",
        },
    },
    "fixtures": {
        "attacker": {"id": "attacker-1"},
        "victim": {
            "id": "victim-1",
            "records": [{"tool": "get_order", "id_arg": "order_id", "id": "order-victim-1"}],
        },
    },
    "canaries": ["GAZUA-CANARY-7f3a9c"],
}
CI_VARIABLES = (
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "TF_BUILD",
    "JENKINS_URL",
    "BUILD_BUILDID",
    "CIRCLECI",
)


def local_environment(**extra: str) -> dict[str, str]:
    """A child environment without any CI indicator, plus ``extra``."""
    environment = {
        name: value for name, value in build_clean_environment().items() if name not in CI_VARIABLES
    }
    environment.update(extra)
    return environment


def gazua(cwd: Path, *arguments: str, env: dict[str, str] | None = None) -> Any:
    return run_process(
        [sys.executable, "-m", "gazua", *arguments],
        cwd=cwd,
        env=env if env is not None else local_environment(),
    )


def echo_project(root: Path, **overrides: Any) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    shutil.copy(ROOT / "tests" / "support" / "echo_target.py", root / "echo_target.py")
    document = {**ECHO_CONFIG, **overrides}
    (root / "gazua.yaml").write_text(json.dumps(document, indent=2), encoding="utf-8")
    (root / ".gitignore").write_text(".gazua/\n", encoding="utf-8")
    return root


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def every_file(folder: Path) -> str:
    return "".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in sorted(folder.rglob("*"))
        if path.is_file()
    )


def without(environment: dict[str, str], *names: str) -> dict[str, str]:
    return {key: value for key, value in environment.items() if key not in names}
