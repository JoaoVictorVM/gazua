import os
import re
import shutil
import sys
import tarfile
import tomllib
import zipfile
from collections.abc import Callable
from email import message_from_string
from email.message import Message
from pathlib import Path

import pytest

FORBIDDEN_PARTS = {".planning", ".harness", ".agents", ".codex", ".claude", ".venv", "tests"}
FORBIDDEN_NAMES = {"AGENTS.md", "CLAUDE.md", ".env"}
FORBIDDEN_SUFFIXES = {".pem", ".key"}
SENTINELS = (
    ".planning/product.md",
    ".harness/state/features.json",
    ".agents/skills/note.md",
    ".codex/note.md",
    ".claude/settings.json",
    "AGENTS.md",
    "CLAUDE.md",
    ".env",
    ".env.local",
    "src/gazua/.env",
    "src/gazua/.env.local",
    "src/gazua/signing.pem",
    "src/gazua/signing.key",
)
SENTINEL_CONTENT = "sentinel-must-not-be-distributed"
PUBLIC_PATHS = ("src", "docs", "README.md", "SECURITY.md", "LICENSE", "pyproject.toml")

Runner = Callable[..., object]


def wheel_in(directory: Path) -> Path:
    return next(directory.glob("*.whl"))


def sdist_in(directory: Path) -> Path:
    return next(directory.glob("*.tar.gz"))


def wheel_entries(wheel: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(wheel) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def sdist_entries(sdist: Path) -> dict[str, bytes]:
    entries: dict[str, bytes] = {}
    with tarfile.open(sdist) as archive:
        for member in archive.getmembers():
            if member.isfile():
                extracted = archive.extractfile(member)
                assert extracted is not None
                name = member.name.split("/", maxsplit=1)[1]
                entries[name] = extracted.read()
    return entries


def forbidden_entries(entries: dict[str, bytes]) -> list[str]:
    found: list[str] = []
    for name, content in entries.items():
        path = Path(name)
        if (
            FORBIDDEN_PARTS.intersection(path.parts)
            or path.name in FORBIDDEN_NAMES
            or path.name.startswith(".env")
            or path.suffix in FORBIDDEN_SUFFIXES
            or SENTINEL_CONTENT.encode() in content
        ):
            found.append(name)
    return found


def metadata_of(text: bytes) -> Message:
    return message_from_string(text.decode("utf-8"))


def scripts_folder(environment: Path) -> Path:
    return environment / ("Scripts" if sys.platform == "win32" else "bin")


def interpreter_of(environment: Path) -> Path:
    return scripts_folder(environment) / ("python.exe" if sys.platform == "win32" else "python")


@pytest.fixture(scope="session")
def manifest(project_root: Path) -> dict[str, object]:
    content = (project_root / "pyproject.toml").read_text(encoding="utf-8")
    return tomllib.loads(content)["project"]


@pytest.fixture(scope="session")
def distributions(project_root: Path, tmp_path_factory: pytest.TempPathFactory, run_isolated):
    """The artifacts under test. A release passes the exact files it is going to publish."""
    supplied = os.environ.get("GAZUA_DIST_DIR")
    if supplied:
        return (project_root / supplied).resolve()
    output = tmp_path_factory.mktemp("dist")
    result = run_isolated(["uv", "build", "--out-dir", output], cwd=project_root)
    assert result.returncode == 0, result.stderr
    return output


def assert_runs_outside_checkout(run_isolated, command: list[str | Path], cwd: Path) -> None:
    version = run_isolated([*command, "--version"], cwd=cwd)
    assert version.returncode == 0, version.stderr
    assert re.fullmatch(r"gazua \S+\n", version.stdout)

    help_result = run_isolated([*command, "--help"], cwd=cwd)
    assert help_result.returncode == 0, help_result.stderr
    assert "--version" in help_result.stdout


def test_wheel_and_sdist_metadata(distributions: Path, manifest: dict[str, object]) -> None:
    version = manifest["version"]
    wheel = wheel_in(distributions)
    sdist = sdist_in(distributions)
    assert wheel.name == f"gazua-{version}-py3-none-any.whl"
    assert sdist.name == f"gazua-{version}.tar.gz"

    wheel_files = wheel_entries(wheel)
    sdist_files = sdist_entries(sdist)
    dist_info = f"gazua-{version}.dist-info"
    for metadata in (
        metadata_of(wheel_files[f"{dist_info}/METADATA"]),
        metadata_of(sdist_files["PKG-INFO"]),
    ):
        assert metadata["Name"] == "gazua"
        assert metadata["Version"] == version
        assert metadata["Requires-Python"] == ">=3.11"
        assert metadata["License-Expression"] == "Apache-2.0"
        assert metadata["License-File"] == "LICENSE"
        assert metadata.get_all("Provides-Extra") is None
        required = {
            re.split(r"[<>=!~ ;\[]", requirement, maxsplit=1)[0].lower()
            for requirement in metadata.get_all("Requires-Dist") or []
        }
        assert required == {"jinja2", "pydantic", "pyyaml", "typer"}

    entry_points = wheel_files[f"{dist_info}/entry_points.txt"].decode("utf-8")
    assert "gazua = gazua._bootstrap:main" in entry_points
    assert "gazua/py.typed" in wheel_files
    assert f"{dist_info}/licenses/LICENSE" in wheel_files
    assert {"LICENSE", "README.md", "SECURITY.md", "docs/releasing.md"} <= set(sdist_files)


def test_distribution_excludes_local_and_secret_files(
    distributions: Path, project_root: Path, tmp_path: Path, run_isolated
) -> None:
    assert forbidden_entries(wheel_entries(wheel_in(distributions))) == []
    assert forbidden_entries(sdist_entries(sdist_in(distributions))) == []

    # The copy has no .gitignore, so the exclusions cannot depend on ignored files.
    source = tmp_path / "source"
    source.mkdir()
    for public_path in PUBLIC_PATHS:
        origin = project_root / public_path
        destination = source / public_path
        if origin.is_dir():
            shutil.copytree(origin, destination, ignore=shutil.ignore_patterns("__pycache__"))
        else:
            shutil.copy(origin, destination)
    for sentinel in SENTINELS:
        path = source / sentinel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(SENTINEL_CONTENT, encoding="utf-8")

    output = tmp_path / "output"
    built = run_isolated(["uv", "build", "--out-dir", output, source], cwd=tmp_path)
    assert built.returncode == 0, built.stderr

    assert forbidden_entries(wheel_entries(wheel_in(output))) == []
    assert forbidden_entries(sdist_entries(sdist_in(output))) == []


def test_sdist_rebuilds_installable_wheel(
    distributions: Path, tmp_path: Path, run_isolated
) -> None:
    extracted = tmp_path / "extracted"
    with tarfile.open(sdist_in(distributions)) as archive:
        archive.extractall(extracted, filter="data")
    source = next(extracted.iterdir())
    output = tmp_path / "rebuilt"
    built = run_isolated(["uv", "build", "--wheel", "--out-dir", output, source], cwd=tmp_path)
    assert built.returncode == 0, built.stderr

    environment = tmp_path / "environment"
    created = run_isolated(["uv", "venv", "--python", sys.executable, environment], cwd=tmp_path)
    assert created.returncode == 0, created.stderr
    installed = run_isolated(
        ["uv", "pip", "install", "--python", interpreter_of(environment), wheel_in(output)],
        cwd=tmp_path,
    )
    assert installed.returncode == 0, installed.stderr

    assert_runs_outside_checkout(run_isolated, [scripts_folder(environment) / "gazua"], tmp_path)


def test_pip_install_runs_outside_checkout(
    distributions: Path, tmp_path: Path, run_isolated
) -> None:
    environment = tmp_path / "environment"
    created = run_isolated(
        ["uv", "venv", "--seed", "--python", sys.executable, environment], cwd=tmp_path
    )
    assert created.returncode == 0, created.stderr
    python = interpreter_of(environment)

    installed = run_isolated(
        [python, "-m", "pip", "install", wheel_in(distributions)], cwd=tmp_path
    )
    assert installed.returncode == 0, installed.stderr

    assert_runs_outside_checkout(run_isolated, [scripts_folder(environment) / "gazua"], tmp_path)
    assert_runs_outside_checkout(run_isolated, [python, "-m", "gazua"], tmp_path)


def test_uv_tool_install_runs_outside_checkout(
    distributions: Path, tmp_path: Path, run_isolated, clean_environment
) -> None:
    tools = tmp_path / "tools"
    binaries = tmp_path / "bin"
    environment = {
        **clean_environment(),
        "UV_TOOL_DIR": str(tools),
        "UV_TOOL_BIN_DIR": str(binaries),
    }

    installed = run_isolated(
        ["uv", "tool", "install", "--python", sys.executable, wheel_in(distributions)],
        cwd=tmp_path,
        env=environment,
    )
    assert installed.returncode == 0, installed.stderr

    assert_runs_outside_checkout(run_isolated, [binaries / "gazua"], tmp_path)


@pytest.mark.python310
@pytest.mark.parametrize("installer", ["pip", "uv"])
def test_python_metadata_rejects_unsupported_install(
    distributions: Path, python310: str, tmp_path: Path, run_isolated, installer: str
) -> None:
    environment = tmp_path / "environment"
    created = run_isolated(
        ["uv", "venv", "--seed", "--python", python310, environment], cwd=tmp_path
    )
    assert created.returncode == 0, created.stderr
    python = interpreter_of(environment)
    command: list[str | Path] = (
        [python, "-m", "pip", "install"]
        if installer == "pip"
        else ["uv", "pip", "install", "--python", python]
    )

    rejected = run_isolated([*command, wheel_in(distributions)], cwd=tmp_path)

    assert rejected.returncode != 0
    assert "3.11" in rejected.stdout + rejected.stderr
