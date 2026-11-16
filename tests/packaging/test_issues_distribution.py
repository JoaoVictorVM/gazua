import json
import os
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from conftest import SPY

ISSUE_FILES = (
    "issues/__init__.py",
    "issues/export.py",
    "issues/models.py",
    "issues/rendering.py",
    "issues/storage.py",
    "issues/templates/issue.md.j2",
    "reports/guide_models.py",
    "reports/guides/fallback-r1.json",
    "reports/legacy_guides.py",
    "reports/legacy_v2.py",
    "schemas/run-v3.schema.json",
)


@pytest.fixture(scope="module")
def built(project_root: Path, tmp_path_factory: pytest.TempPathFactory, run_isolated) -> Path:
    supplied = os.environ.get("GAZUA_DIST_DIR")
    if supplied:
        return (project_root / supplied).resolve()
    output = tmp_path_factory.mktemp("issues-dist")
    result = run_isolated(["uv", "build", "--out-dir", output], cwd=project_root)
    assert result.returncode == 0, result.stderr
    return output


@pytest.fixture(scope="module")
def installed(built: Path, tmp_path_factory: pytest.TempPathFactory, run_isolated) -> Path:
    environment = tmp_path_factory.mktemp("issues-env") / "environment"
    created = run_isolated(["uv", "venv", "--python", sys.executable, environment], cwd=built)
    assert created.returncode == 0, created.stderr
    folder = "Scripts" if os.name == "nt" else "bin"
    python = environment / folder / ("python.exe" if os.name == "nt" else "python")
    wheel = next(built.glob("*.whl"))
    done = run_isolated(["uv", "pip", "install", "--python", python, wheel], cwd=built)
    assert done.returncode == 0, done.stderr
    return python


def test_wheel_contains_issue_template_and_v3_schema(built: Path, run_isolated) -> None:
    with zipfile.ZipFile(next(built.glob("*.whl"))) as archive:
        wheel_files = set(archive.namelist())

    for name in ISSUE_FILES:
        assert f"gazua/{name}" in wheel_files, name


def test_sdist_contains_issue_docs(built: Path) -> None:
    with tarfile.open(next(built.glob("*.tar.gz"))) as archive:
        sdist_files = {name.split("/", 1)[1] for name in archive.getnames() if "/" in name}

    for name in ISSUE_FILES:
        assert f"src/gazua/{name}" in sdist_files, name
    assert "docs/fix-guide.md" in sdist_files
    assert "docs/issues.md" in sdist_files


def test_installed_export_is_offline(
    installed: Path, project_root: Path, tmp_path: Path, run_isolated
) -> None:
    sys.path.insert(0, str(project_root / "tests" / "support"))
    try:
        from report_factory import document

        from gazua.reports.storage import document_json

        content = document_json(document())
    finally:
        sys.path.remove(str(project_root / "tests" / "support"))
    work = tmp_path / "work"
    work.mkdir()
    (work / "run.json").write_text(content, encoding="utf-8")
    report = tmp_path / "spy.json"

    shown = run_isolated([installed, "-m", "gazua", "issues", "--help"], cwd=work)
    assert shown.returncode == 0, shown.stderr
    exported = run_isolated(
        [installed, SPY, report, "cli", "issues", "--from", "run.json"], cwd=work
    )

    assert exported.returncode == 0, exported.stderr
    observed = json.loads(report.read_text(encoding="utf-8"))
    assert observed["exit_code"] == 0
    assert observed["network"] == []
    assert observed["processes"] == []
    [folder] = (work / ".gazua" / "issues").iterdir()
    names = sorted(path.name for path in folder.iterdir())
    assert names[-1] == "manifest.json"
    assert len(names) == 2
    issue = (folder / names[0]).read_text(encoding="utf-8")
    assert "## Acceptance criteria" in issue
    assert "Fixes the cause:" in issue
