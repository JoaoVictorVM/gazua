"""MCP test projects: a ``gazua.yaml`` pointing at a synthetic stdio server, and helpers.

Two servers are available. ``python`` runs ``mcp_raw_server.py`` from a JSON scenario that a
test can change mid-run. ``typescript`` runs the compiled fixture of ``tests/support/mcp_server``
with the official TypeScript SDK; it keeps its state in files of a folder given as argument.
Both append every call they receive to a file, which is how a test proves what was forwarded.
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SUPPORT = ROOT / "tests" / "support"
RAW_SERVER = SUPPORT / "mcp_raw_server.py"
TS_FOLDER = SUPPORT / "mcp_server"
TS_SERVER = TS_FOLDER / "dist" / "server.js"
REQUIRE_ENV = "GAZUA_REQUIRE_MCP"
ATTACKER = "attacker"
VICTIM = "victim"

ORDER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "order_id": {"type": "string"},
        "actor_id": {"type": "string"},
        "owner_id": {"type": "string"},
    },
    "required": ["order_id", "actor_id"],
    "additionalProperties": False,
}
EMAIL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
    "required": ["to"],
}
SEARCH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"query": {"type": "string"}},
}
DEFAULT_TOOLS: list[dict[str, Any]] = [
    {"name": "get_order", "description": "Reads one order by id.", "inputSchema": ORDER_SCHEMA},
    {
        "name": "search_docs",
        "description": "Searches the help center.",
        "inputSchema": SEARCH_SCHEMA,
    },
    {"name": "send_email", "description": "Sends an email.", "inputSchema": EMAIL_SCHEMA},
]
ORDERS = {"order-victim": VICTIM, "order-attacker": ATTACKER}


def require_mcp() -> None:
    """Skips without the extra, unless the MCP matrix demands it: then it fails instead."""
    from gazua.mcp import extra_available

    if not extra_available():
        if os.environ.get(REQUIRE_ENV):
            pytest.fail("The MCP extra is required in this job.")
        pytest.skip("gazua[mcp] is not installed.")


def require_typescript() -> str:
    """The node executable, when the compiled TypeScript fixture is available."""
    require_mcp()
    node = shutil.which("node")
    if node is None or not TS_SERVER.is_file():
        if os.environ.get(REQUIRE_ENV):
            pytest.fail("The TypeScript MCP fixture must be built in this job.")
        pytest.skip("The TypeScript MCP fixture is not built (npm ci && npm run build).")
    return node


def base_config(server: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mcp": server,
        "tools": {
            "get_order": {
                "safe": True,
                "sensitive": False,
                "actor_arg": "actor_id",
                "owner_arg": "owner_id",
            },
            "search_docs": {"safe": True, "sensitive": False},
            "send_email": {"safe": False, "sensitive": True, "dry_run_return": "queued"},
        },
        "fixtures": {
            "attacker": {"id": ATTACKER},
            "victim": {
                "id": VICTIM,
                "records": [{"tool": "get_order", "id_arg": "order_id", "id": "order-victim"}],
            },
        },
        "limits": {"timeout": 60, "concurrency": 1},
    }


class McpProject:
    """One project folder with its server state, configuration and call counter."""

    def __init__(self, root: Path, server: str = "python") -> None:
        require_mcp()
        self.root = root
        self.server = server
        self.state = root / "server-state"
        self.state.mkdir(parents=True, exist_ok=True)
        self.calls_file = self.state / "calls.jsonl"
        if server == "python":
            self.scenario_path = self.state / "scenario.json"
            self.tools_path = self.state / "tools.json"
            self.scenario: dict[str, Any] = {
                "tools_file": str(self.tools_path),
                "calls_file": str(self.calls_file),
                "orders": dict(ORDERS),
                "mode": "vulnerable",
            }
            self.save_scenario()
            self.set_tools(DEFAULT_TOOLS)
            launch = {
                "transport": "stdio",
                "command": sys.executable,
                "args": [str(RAW_SERVER), str(self.scenario_path)],
                "cwd": ".",
            }
        else:
            node = require_typescript()
            launch = {
                "transport": "stdio",
                "command": node,
                "args": [str(TS_SERVER), str(self.state)],
                "cwd": ".",
            }
        self.config: dict[str, Any] = base_config(launch)
        self.write()

    # State

    def save_scenario(self) -> None:
        self.scenario_path.write_text(json.dumps(self.scenario), encoding="utf-8")

    def set_tools(self, tools: Sequence[dict[str, Any]], page_size: int | None = None) -> None:
        """The python server's pages. ``page_size`` splits them with chained cursors."""
        items = list(tools)
        size = page_size or max(len(items), 1)
        chunks = [items[index : index + size] for index in range(0, len(items), size)] or [[]]
        pages = [
            {"tools": chunk, "next": f"page-{index + 1}" if index + 1 < len(chunks) else None}
            for index, chunk in enumerate(chunks)
        ]
        self.tools_path.write_text(json.dumps({"pages": pages}), encoding="utf-8")

    def set_pages(self, pages: list[dict[str, Any]]) -> None:
        self.tools_path.write_text(json.dumps({"pages": pages}), encoding="utf-8")

    def harden(self) -> None:
        if self.server == "python":
            self.scenario["mode"] = "hardened"
            self.save_scenario()
        else:
            (self.state / "hardened").write_text("x", encoding="utf-8")

    def flag(self, name: str) -> None:
        (self.state / name).write_text("x", encoding="utf-8")

    def write(self, **overrides: Any) -> Path:
        document = copy.deepcopy(self.config)
        document.update(overrides)
        path = self.root / "gazua.yaml"
        path.write_text(json.dumps(document, indent=2), encoding="utf-8")
        return path

    def update(self, **overrides: Any) -> None:
        self.config.update(overrides)
        self.write()

    def calls(self) -> list[dict[str, Any]]:
        if not self.calls_file.is_file():
            return []
        return [
            json.loads(line)
            for line in self.calls_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def clear_calls(self) -> None:
        self.calls_file.unlink(missing_ok=True)

    # Runs

    def load(self) -> Any:
        from gazua.config.loader import load_config

        return load_config(self.root / "gazua.yaml").config

    def run_tools(
        self,
        mold: str | None = None,
        *,
        molds: Sequence[str] | None = None,
        overrides: dict[str, Any] | None = None,
        **options: Any,
    ) -> Any:
        from gazua.catalog.loader import load_catalog
        from gazua.modes.tools import run_tools
        from gazua.modes.tools_models import ToolsOptions
        from gazua.runtime.run_models import LimitOverrides

        config = self.load()
        chosen = ToolsOptions(mold=mold, overrides=LimitOverrides.model_validate(overrides or {}))
        entries = load_catalog(config, config_dir=self.root).entries
        if molds is not None:
            entries = tuple(entry for entry in entries if entry.id in molds)
        return run_tools(config, entries, chosen, self.root, **options)

    def run_agent(
        self,
        mold: str | None = None,
        *,
        molds: Sequence[str] | None = None,
        overrides: dict[str, Any] | None = None,
        repetitions: int | None = None,
        **options: Any,
    ) -> Any:
        from gazua.catalog.loader import load_catalog
        from gazua.modes.agent import run_agent
        from gazua.modes.agent_models import AgentOptions
        from gazua.runtime.run_models import LimitOverrides

        config = self.load()
        chosen = AgentOptions(
            mold=mold,
            repetitions=repetitions,
            overrides=LimitOverrides.model_validate({"concurrency": 1, **(overrides or {})}),
        )
        entries = load_catalog(config, config_dir=self.root, release="v0.4").entries
        if molds is not None:
            entries = tuple(entry for entry in entries if entry.id in molds)
        return run_agent(config, entries, chosen, self.root, **options)

    def use_agent(self, behavior: str = "follow") -> None:
        """Copies the simulated MCP agent and points the entrypoint at it."""
        shutil.copy(SUPPORT / "mcp_agent.py", self.root / "mcp_agent.py")
        (self.root / "agent-behavior").write_text(behavior, encoding="utf-8")
        self.update(entrypoint="mcp_agent:entrypoint")

    def cli(
        self, *arguments: str, env: dict[str, str] | None = None, timeout: float = 300
    ) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ if env is None else env)
        environment["PYTHONIOENCODING"] = "utf-8"
        return subprocess.run(
            [sys.executable, "-m", "gazua", *arguments],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout,
            check=False,
        )
