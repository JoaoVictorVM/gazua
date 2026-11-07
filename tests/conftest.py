import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPY = ROOT / "tests" / "support" / "app_spy.py"
FAKE_CREDENTIALS = {
    "OPENAI_API_KEY": "sentinel-not-a-real-key",
    "ANTHROPIC_API_KEY": "sentinel-not-a-real-key",
    "AWS_SECRET_ACCESS_KEY": "sentinel-not-a-real-key",
}
CREDENTIAL_SHAPE = re.compile(r"(_API_KEY|_TOKEN|_SECRET|_PASSWORD|^AWS_|^PYPI_)", re.IGNORECASE)


def clean_environment() -> dict[str, str]:
    """Child environment without the checkout on the path and without real credentials."""
    return {
        name: value
        for name, value in os.environ.items()
        if name != "PYTHONPATH" and not CREDENTIAL_SHAPE.search(name)
    }


def run_process(
    command: Sequence[str | Path],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    timeout: float = 300,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(part) for part in command],
        cwd=cwd,
        env=clean_environment() if env is None else env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=timeout,
        check=False,
    )


@pytest.fixture(scope="session")
def project_root() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def console_script() -> Path:
    found = shutil.which("gazua", path=str(Path(sys.executable).parent))
    assert found, "the development environment must have the gazua console script installed"
    return Path(found)


@pytest.fixture
def entrypoints(console_script: Path) -> dict[str, list[str]]:
    return {
        "console script": [str(console_script)],
        "module": [sys.executable, "-m", "gazua"],
    }


@pytest.fixture
def workdir(tmp_path: Path) -> Path:
    path = tmp_path / "workdir"
    path.mkdir()
    return path


@pytest.fixture
def run_spied(tmp_path: Path, workdir: Path) -> Callable[..., dict[str, Any]]:
    """Runs the observed process with fake credentials available in its environment."""

    def run(mode: str, *arguments: str) -> dict[str, Any]:
        report_path = tmp_path / "spy-report.json"
        result = run_process(
            [sys.executable, SPY, report_path, mode, *arguments],
            cwd=workdir,
            env={**clean_environment(), **FAKE_CREDENTIALS},
        )
        assert report_path.exists(), result.stderr
        return json.loads(report_path.read_text(encoding="utf-8"))

    return run


@pytest.fixture(scope="session")
def python310() -> str:
    """A real Python 3.10. Setting GAZUA_PYTHON310 turns a missing interpreter into a failure."""
    configured = os.environ.get("GAZUA_PYTHON310")
    if configured:
        return configured
    uv = shutil.which("uv")
    if uv:
        found = subprocess.run(
            [uv, "python", "find", "--no-project", "3.10"],
            capture_output=True,
            text=True,
            check=False,
        )
        if found.returncode == 0 and found.stdout.strip():
            return found.stdout.strip()
    pytest.skip("Python 3.10 is not available")
