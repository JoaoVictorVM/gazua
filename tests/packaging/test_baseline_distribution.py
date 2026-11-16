import os
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

BASELINE_FILES = (
    "baseline/__init__.py",
    "baseline/comparison.py",
    "baseline/models.py",
    "baseline/plan.py",
    "baseline/presentation.py",
    "baseline/selection.py",
    "baseline/storage.py",
    "baseline/verification.py",
    "reports/legacy.py",
    "schemas/baseline-v1.schema.json",
    "schemas/run-v1.schema.json",
    "schemas/run-v2.schema.json",
)


@pytest.fixture(scope="module")
def built(project_root: Path, tmp_path_factory: pytest.TempPathFactory, run_isolated) -> Path:
    supplied = os.environ.get("GAZUA_DIST_DIR")
    if supplied:
        return (project_root / supplied).resolve()
    output = tmp_path_factory.mktemp("baseline-dist")
    result = run_isolated(["uv", "build", "--out-dir", output], cwd=project_root)
    assert result.returncode == 0, result.stderr
    return output


def test_baseline_schema_docs_and_commands_are_installed(
    built: Path, project_root: Path, tmp_path: Path, run_isolated
) -> None:
    wheel = next(built.glob("*.whl"))
    with zipfile.ZipFile(wheel) as archive:
        wheel_files = set(archive.namelist())
    with tarfile.open(next(built.glob("*.tar.gz"))) as archive:
        sdist_files = {name.split("/", 1)[1] for name in archive.getnames() if "/" in name}
    for name in BASELINE_FILES:
        assert f"gazua/{name}" in wheel_files
        assert f"src/gazua/{name}" in sdist_files
    assert "docs/baseline.md" in sdist_files

    environment = tmp_path / "environment"
    created = run_isolated(["uv", "venv", "--python", sys.executable, environment], cwd=tmp_path)
    assert created.returncode == 0, created.stderr
    folder = "Scripts" if os.name == "nt" else "bin"
    python = environment / folder / ("python.exe" if os.name == "nt" else "python")
    installed = run_isolated(["uv", "pip", "install", "--python", python, wheel], cwd=tmp_path)
    assert installed.returncode == 0, installed.stderr
    for command in ("baseline", "verify"):
        shown = run_isolated([python, "-m", "gazua", command, "--help"], cwd=tmp_path)
        assert shown.returncode == 0, shown.stderr
    verify_help = run_isolated([python, "-m", "gazua", "verify", "--help"], cwd=tmp_path)
    assert "20 times" in verify_help.stdout
    probe = "\n".join(
        [
            "from gazua.baseline.models import packaged_baseline_json_schema, "
            "render_baseline_json_schema",
            "from gazua.reports.legacy import packaged_run_v1_json_schema, "
            "render_run_v1_json_schema",
            "assert packaged_baseline_json_schema().splitlines() == "
            "render_baseline_json_schema().splitlines()",
            "assert packaged_run_v1_json_schema().splitlines() == "
            "render_run_v1_json_schema().splitlines()",
            "print('ok')",
        ]
    )
    result = run_isolated([python, "-c", probe], cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"
