import json
import os
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

CI_FILES = (
    "ci/__init__.py",
    "ci/action.py",
    "ci/comment.py",
    "ci/environment.py",
    "ci/github.py",
    "ci/models.py",
    "ci/projection.py",
    "ci/sarif.py",
    "ci/storage.py",
    "pytest_plugin.py",
    "pytest_models.py",
    "schemas/ci-summary-v1.schema.json",
    "schemas/pr-comment-v1.schema.json",
    "schemas/gazua-sarif-v1.schema.json",
)


@pytest.fixture(scope="module")
def built(project_root: Path, tmp_path_factory: pytest.TempPathFactory, run_isolated) -> Path:
    supplied = os.environ.get("GAZUA_DIST_DIR")
    if supplied:
        return (project_root / supplied).resolve()
    output = tmp_path_factory.mktemp("ci-dist")
    result = run_isolated(["uv", "build", "--out-dir", output], cwd=project_root)
    assert result.returncode == 0, result.stderr
    return output


@pytest.fixture(scope="module")
def installed(built: Path, tmp_path_factory: pytest.TempPathFactory, run_isolated) -> Path:
    folder = tmp_path_factory.mktemp("ci-env")
    environment = folder / "environment"
    created = run_isolated(["uv", "venv", "--python", sys.executable, environment], cwd=folder)
    assert created.returncode == 0, created.stderr
    scripts = "Scripts" if os.name == "nt" else "bin"
    python = environment / scripts / ("python.exe" if os.name == "nt" else "python")
    wheel = next(built.glob("*.whl"))
    result = run_isolated(["uv", "pip", "install", "--python", python, wheel, "pytest"], cwd=folder)
    assert result.returncode == 0, result.stderr
    return python


def test_wheel_contains_ci_modules_and_schemas(built: Path) -> None:
    with zipfile.ZipFile(next(built.glob("*.whl"))) as archive:
        names = set(archive.namelist())
        [entry_points] = [name for name in names if name.endswith("entry_points.txt")]
        points = archive.read(entry_points).decode("utf-8")

    for name in CI_FILES:
        assert f"gazua/{name}" in names
    assert "[pytest11]" in points
    assert "gazua = gazua.pytest_plugin" in points


def test_sdist_contains_action_and_examples(built: Path) -> None:
    with tarfile.open(next(built.glob("*.tar.gz"))) as archive:
        names = {name.split("/", 1)[1] for name in archive.getnames() if "/" in name}

    for name in CI_FILES:
        assert f"src/gazua/{name}" in names
    for name in (
        "action.yml",
        "docs/ci.md",
        "docs/pytest.md",
        "docs/examples/gazua-github-actions.yml",
    ):
        assert name in names


def test_installed_sarif_is_offline(
    installed: Path, project_root: Path, tmp_path: Path, run_isolated
) -> None:
    (tmp_path / "run.json").write_bytes(
        (project_root / "tests/support/run-example.json").read_bytes()
    )
    probe = (
        "import socket, sys\n"
        "def refuse(*a, **k):\n"
        "    raise SystemExit('network')\n"
        "socket.socket = refuse\n"
        "socket.create_connection = refuse\n"
        "from gazua.cli import main\n"
        "sys.argv = ['gazua', 'sarif', '--from', 'run.json']\n"
        "main()\n"
    )

    result = run_isolated([installed, "-c", probe], cwd=tmp_path)

    assert result.returncode == 0, result.stderr
    data = json.loads((tmp_path / ".gazua/ci/gazua.sarif").read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"


def test_pytest11_entrypoint_loads(installed: Path, tmp_path: Path, run_isolated) -> None:
    (tmp_path / "test_x.py").write_text("def test_x():\n    pass\n", encoding="utf-8")

    listed = run_isolated([installed, "-m", "pytest", "--help"], cwd=tmp_path)
    plain = run_isolated([installed, "-m", "pytest", "-q", "-p", "no:cacheprovider"], cwd=tmp_path)

    assert listed.returncode == 0, listed.stderr
    assert "--gazua-mold" in listed.stdout
    assert plain.returncode == 0, plain.stdout
    assert not (tmp_path / ".gazua").exists()
