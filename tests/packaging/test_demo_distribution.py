"""The installed package runs the demo by itself: no checkout, no test support, no network."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import pytest

DEMO_FILES = (
    "gazua/demo/__init__.py",
    "gazua/demo/fixtures.py",
    "gazua/demo/models.py",
    "gazua/demo/presentation.py",
    "gazua/demo/runner.py",
    "gazua/demo/script.py",
    "gazua/demo/target.py",
    "gazua/demo/workspace.py",
    "gazua/demo/resources/gazua.yaml",
    "gazua/demo/resources/index.html.j2",
    "gazua/reports/execution.py",
)


@pytest.fixture(scope="module")
def built(project_root: Path, tmp_path_factory: pytest.TempPathFactory, run_isolated: Any) -> Path:
    supplied = os.environ.get("GAZUA_DIST_DIR")
    if supplied:
        return (project_root / supplied).resolve()
    output = tmp_path_factory.mktemp("demo-dist")
    result = run_isolated(["uv", "build", "--out-dir", output], cwd=project_root)
    assert result.returncode == 0, result.stderr
    return output


def _scripts(environment: Path) -> Path:
    return environment / ("Scripts" if sys.platform == "win32" else "bin")


def test_installed_wheel_runs_demo_outside_checkout(
    built: Path, tmp_path: Path, run_isolated: Any, clean_environment: Any
) -> None:
    environment = tmp_path / "environment"
    created = run_isolated(["uv", "venv", "--python", sys.executable, environment], cwd=tmp_path)
    assert created.returncode == 0, created.stderr
    python = _scripts(environment) / ("python.exe" if sys.platform == "win32" else "python")
    installed = run_isolated(
        ["uv", "pip", "install", "--python", python, next(built.glob("*.whl"))], cwd=tmp_path
    )
    assert installed.returncode == 0, installed.stderr
    host = tmp_path / "host"
    host.mkdir()

    located = run_isolated(
        [python, "-c", "import gazua.demo.target as t, sys; print(t.__file__); print(sys.path)"],
        cwd=host,
    )
    result = subprocess.run(
        [_scripts(environment) / "gazua", "demo", "--no-open"],
        cwd=host,
        env=clean_environment(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=900,
        check=False,
    )

    assert located.returncode == 0, located.stderr
    assert Path(located.stdout.splitlines()[0]).is_relative_to(environment)
    assert "tests" not in located.stdout.splitlines()[1].replace("\\", "/").split("/")
    assert result.returncode == 1, result.stderr
    workspace = host / "gazua-demo"
    assert (workspace / "index.html").is_file()
    modes = sorted(
        json.loads(path.read_text(encoding="utf-8"))["metadata"]["mode"]
        for path in (workspace / ".gazua" / "runs").glob("*/run.json")
    )
    assert modes == ["agent", "tools"]


def test_sdist_build_includes_demo_resources(built: Path, project_root: Path) -> None:
    with zipfile.ZipFile(next(built.glob("*.whl"))) as archive:
        wheel = {name: archive.read(name) for name in archive.namelist()}
    with tarfile.open(next(built.glob("*.tar.gz"))) as archive:
        sdist: dict[str, bytes] = {}
        for member in archive.getmembers():
            extracted = archive.extractfile(member) if member.isfile() else None
            if extracted is not None:
                sdist[member.name.split("/", maxsplit=1)[1]] = extracted.read()

    for name in DEMO_FILES:
        assert name in wheel, name
        assert f"src/{name}" in sdist, name
        source = (project_root / "src" / name).read_bytes().replace(b"\r\n", b"\n")
        assert wheel[name].replace(b"\r\n", b"\n") == source
    assert "docs/demo.md" in sdist
    assert not [name for name in wheel if "demo_spy" in name or "demo_support" in name]
