"""Full demo runs shared by the integration tests, and the projections they compare.

A full demo takes about a minute, so each kind of run happens once per session and the tests
read what it left: the process result, the workspace, the two run documents and the spy log.
"""

from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SPY_SITE = Path(__file__).parent / "demo_spy"
DEMO_TIMEOUT = 900
VOLATILE_PROOF = frozenset({"execution_id", "reference"})


@dataclass(frozen=True)
class DemoRun:
    """One finished ``gazua demo`` and what it produced."""

    host: Path
    result: subprocess.CompletedProcess[str]
    spy: Path | None = None

    @property
    def workspace(self) -> Path:
        return self.host / "gazua-demo"

    def documents(self) -> dict[str, dict[str, Any]]:
        """The run documents the index of this run links, by mode."""
        index = (self.workspace / "index.html").read_text(encoding="utf-8")
        found: dict[str, dict[str, Any]] = {}
        for path in sorted((self.workspace / ".gazua" / "runs").glob("*/run.json")):
            relative = path.relative_to(self.workspace).as_posix()
            if relative not in index:
                continue
            document = json.loads(path.read_text(encoding="utf-8"))
            found[document["metadata"]["mode"]] = document
        return found

    def spy_events(self) -> list[dict[str, Any]]:
        assert self.spy is not None
        events: list[dict[str, Any]] = []
        for path in sorted(self.spy.glob("*.jsonl")):
            events.extend(
                json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            )
        return events


def run_demo_process(
    host: Path, env: dict[str, str], *arguments: str, timeout: float = DEMO_TIMEOUT
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "gazua", "demo", "--no-open", *arguments],
        cwd=host,
        env=env,
        capture_output=True,
        text=True,
        # Piped output on Windows uses the legacy code page; the tests read only ASCII text.
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def copy_workspace(source: Path, destination: Path) -> Path:
    shutil.copytree(source, destination)
    return destination


def is_loopback(address: str) -> bool:
    """True for loopback hosts and local socket paths, from the spy's repr of the address."""
    text = address.strip()
    if text in ("None", "''"):
        return True
    if text.startswith("("):
        text = text[1:].split(",", 1)[0].strip()
    text = text.strip("'\"")
    if text in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(text).is_loopback
    except ValueError:
        # A plain string that is not an address is a local socket path.
        return "/" in text or "\\" in text


def semantic(document: dict[str, Any]) -> dict[str, Any]:
    """What must not change between runs: selection, states, findings, proofs and rates.

    Run ids, execution ids, timestamps, durations, paths and process data are left out; the
    proof content and every verdict field stay as they are.
    """
    results = [
        {key: value for key, value in result.items() if key not in ("proof",)}
        | {
            "proof": [
                {key: value for key, value in proof.items() if key not in VOLATILE_PROOF}
                for proof in result.get("proof", [])
            ]
        }
        for result in document["verdicts"]["results"]
    ]
    proofs = [
        {
            "attack_key": proof["attack_key"],
            "proof_index": proof["proof_index"],
            "source": proof["source"],
            "signal": proof["locator"]["signal"],
            "facts": proof["locator"].get("facts"),
            "content": proof["content"],
        }
        for proof in document["proofs"]
    ]
    legitimate = document.get("legitimate_use")
    return {
        "mode": document["metadata"]["mode"],
        "model": document["metadata"]["model"],
        "target_version": document["metadata"]["target_version"],
        "scenarios": document["scenarios"],
        "results": results,
        "findings": document["findings"],
        "proofs": proofs,
        "counts": document["engine"]["counts"],
        "exit": document["report_exit_code"],
        "legitimate": None
        if legitimate is None
        else {key: value for key, value in legitimate.items() if key not in ("tasks",)}
        | {
            "tasks": [
                {k: v for k, v in task.items() if k != "execution_id"}
                for task in legitimate.get("tasks", [])
            ]
        },
    }
