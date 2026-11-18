import json
import os
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

MCP_FILES = (
    "mcp/__init__.py",
    "mcp/broker.py",
    "mcp/client.py",
    "mcp/discovery.py",
    "mcp/evidence.py",
    "mcp/executor.py",
    "mcp/models.py",
    "mcp/policy.py",
    "mcp/proxy.py",
    "reports/legacy_v3.py",
    "schemas/mcp-delivery-v1.schema.json",
    "schemas/run-v4.schema.json",
)
CONFIG = {
    "schema_version": 1,
    "mcp": {"transport": "stdio", "command": "node", "args": ["server.js"]},
    "tools": {},
}


@pytest.fixture(scope="module")
def built(project_root: Path, tmp_path_factory: pytest.TempPathFactory, run_isolated) -> Path:
    supplied = os.environ.get("GAZUA_DIST_DIR")
    if supplied:
        return (project_root / supplied).resolve()
    output = tmp_path_factory.mktemp("mcp-dist")
    result = run_isolated(["uv", "build", "--out-dir", output], cwd=project_root)
    assert result.returncode == 0, result.stderr
    return output


def _environment(built: Path, factory: pytest.TempPathFactory, run_isolated, spec: str) -> Path:
    environment = factory.mktemp("mcp-env") / "environment"
    created = run_isolated(["uv", "venv", "--python", sys.executable, environment], cwd=built)
    assert created.returncode == 0, created.stderr
    folder = "Scripts" if os.name == "nt" else "bin"
    python = environment / folder / ("python.exe" if os.name == "nt" else "python")
    wheel = next(built.glob("*.whl")).resolve()
    target = spec.format(wheel=wheel.as_uri())
    done = run_isolated(["uv", "pip", "install", "--python", python, target], cwd=built)
    assert done.returncode == 0, done.stderr
    return python


@pytest.fixture(scope="module")
def base(built: Path, tmp_path_factory: pytest.TempPathFactory, run_isolated) -> Path:
    return _environment(built, tmp_path_factory, run_isolated, "gazua @ {wheel}")


@pytest.fixture(scope="module")
def extra(built: Path, tmp_path_factory: pytest.TempPathFactory, run_isolated) -> Path:
    return _environment(built, tmp_path_factory, run_isolated, "gazua[mcp] @ {wheel}")


def test_wheel_and_sdist_carry_the_adapter_and_its_docs(built: Path) -> None:
    with zipfile.ZipFile(next(built.glob("*.whl"))) as archive:
        wheel_files = set(archive.namelist())
        metadata = next(
            archive.read(name).decode("utf-8")
            for name in wheel_files
            if name.endswith(".dist-info/METADATA")
        )
    with tarfile.open(next(built.glob("*.tar.gz"))) as archive:
        sdist_files = {name.split("/", 1)[1] for name in archive.getnames() if "/" in name}

    for name in MCP_FILES:
        assert f"gazua/{name}" in wheel_files, name
        assert f"src/gazua/{name}" in sdist_files, name
    assert "docs/mcp.md" in sdist_files
    assert "Provides-Extra: mcp" in metadata
    assert not any("mcp_server" in name or "node_modules" in name for name in sdist_files)


def test_base_install_without_mcp_and_extra_with_mcp(
    base: Path, extra: Path, tmp_path: Path, run_isolated
) -> None:
    light = run_isolated(
        [
            base,
            "-c",
            "import sys, gazua.cli, gazua.mcp, gazua.mcp.models; "
            "assert 'mcp.client' not in sys.modules and 'jsonschema' not in sys.modules; "
            "assert not gazua.mcp.extra_available()",
        ],
        cwd=tmp_path,
    )
    assert light.returncode == 0, light.stderr
    (tmp_path / "gazua.yaml").write_text(json.dumps(CONFIG), encoding="utf-8")

    refused = run_isolated([base, "-m", "gazua", "run", "--tools"], cwd=tmp_path)

    assert refused.returncode == 2
    assert "Install gazua[mcp]" in refused.stderr
    init = run_isolated([base, "-m", "gazua", "init", "--mcp", "node"], cwd=tmp_path / ".")
    assert init.returncode == 2
    assert "Install gazua[mcp]" in init.stderr

    available = run_isolated(
        [extra, "-c", "import gazua.mcp, gazua.mcp.client; assert gazua.mcp.extra_available()"],
        cwd=tmp_path,
    )
    assert available.returncode == 0, available.stderr
    proxy = run_isolated([extra, "-m", "gazua", "mcp-proxy"], cwd=tmp_path)
    assert proxy.returncode == 2
    assert proxy.stdout == ""
