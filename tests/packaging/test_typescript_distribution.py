import json
import os
import shutil
import sys
import zipfile
from pathlib import Path

import pytest

from conftest import build_clean_environment

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "packages" / "typescript"
AGENT_JS = ROOT / "tests" / "support" / "typescript_agent" / "dist" / "agent.js"
REQUIRE_ENV = "GAZUA_REQUIRE_TYPESCRIPT"
TYPESCRIPT_FILES = (
    "typescript/__init__.py",
    "typescript/executor.py",
    "typescript/launcher.mjs",
    "typescript/models.py",
    "typescript/policy.py",
    "typescript/process.py",
    "schemas/typescript-runner-v1.schema.json",
    "schemas/run-v6.schema.json",
)
RUNTIME_FILES = {
    "LICENSE",
    "README.md",
    "package.json",
    "schemas/call-record-v1.schema.json",
    "schemas/session-v2.schema.json",
    "schemas/typescript-runner-v1.schema.json",
}


def tools() -> tuple[str, str]:
    node, npm = shutil.which("node"), shutil.which("npm")
    if node is None or npm is None or not (PACKAGE / "dist" / "runner.js").is_file():
        if os.environ.get(REQUIRE_ENV):
            pytest.fail("Node, npm and the built npm package are required in this job.")
        pytest.skip("Node, npm or the built npm package is missing.")
    return node, npm


@pytest.fixture(scope="module")
def tarball(tmp_path_factory: pytest.TempPathFactory, run_isolated) -> Path:
    _, npm = tools()
    supplied = os.environ.get("GAZUA_NPM_DIR")
    if supplied:
        # The release validates the tarball it built, never a new one.
        return next((ROOT / supplied).resolve().glob("gazua-*.tgz"))
    output = tmp_path_factory.mktemp("npm-pack")
    packed = run_isolated(
        [npm, "pack", "--ignore-scripts", "--pack-destination", output], cwd=PACKAGE
    )
    assert packed.returncode == 0, packed.stderr
    return next(output.glob("gazua-*.tgz"))


def test_npm_pack_contains_only_runtime_types_schemas_and_license(run_isolated) -> None:
    _, npm = tools()
    listed = run_isolated([npm, "pack", "--dry-run", "--json", "--ignore-scripts"], cwd=PACKAGE)
    assert listed.returncode == 0, listed.stderr
    [summary] = json.loads(listed.stdout)
    files = {item["path"] for item in summary["files"]}
    extra = {
        name
        for name in files - RUNTIME_FILES
        if not (name.startswith("dist/") and name.endswith((".js", ".d.ts", ".js.map")))
    }
    assert extra == set()
    assert files >= RUNTIME_FILES
    assert {"dist/index.js", "dist/index.d.ts", "dist/runner.js"} <= files
    assert not any(name.startswith(("src/", "test/", "build/")) for name in files)
    manifest = json.loads((PACKAGE / "package.json").read_text(encoding="utf-8"))
    assert "dependencies" not in manifest
    assert manifest["type"] == "module"
    assert set(manifest["exports"]) == {".", "./runner", "./package.json"}
    for name in ("session-v2.schema.json", "call-record-v1.schema.json"):
        shipped = (PACKAGE / "schemas" / name).read_text("utf-8").replace("\r\n", "\n")
        source = (ROOT / "src/gazua/schemas" / name).read_text("utf-8").replace("\r\n", "\n")
        assert shipped == source


def test_installed_wheel_finds_installed_npm_runner(
    tmp_path: Path, tarball: Path, run_isolated
) -> None:
    _, npm = tools()
    if not AGENT_JS.is_file():
        pytest.skip("The TypeScript fixture agent is not built.")
    built = tmp_path / "dist"
    supplied = os.environ.get("GAZUA_DIST_DIR")
    if supplied:
        built = (ROOT / supplied).resolve()
    else:
        result = run_isolated(["uv", "build", "--wheel", "--out-dir", built], cwd=ROOT)
        assert result.returncode == 0, result.stderr
    wheel = next(built.glob("*.whl"))
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
    for name in TYPESCRIPT_FILES:
        assert f"gazua/{name}" in names, name

    environment = tmp_path / "environment"
    created = run_isolated(["uv", "venv", "--python", sys.executable, environment], cwd=tmp_path)
    assert created.returncode == 0, created.stderr
    folder = "Scripts" if os.name == "nt" else "bin"
    python = environment / folder / ("python.exe" if os.name == "nt" else "python")
    done = run_isolated(["uv", "pip", "install", "--python", python, wheel], cwd=tmp_path)
    assert done.returncode == 0, done.stderr

    project = tmp_path / "project"
    (project / "dist").mkdir(parents=True)
    (project / "package.json").write_text(
        json.dumps({"name": "installed-check", "private": True, "type": "module"}),
        encoding="utf-8",
    )
    installed = run_isolated(
        [npm, "install", "--ignore-scripts", "--no-audit", "--no-fund", "--offline", tarball],
        cwd=project,
    )
    assert installed.returncode == 0, installed.stderr
    shutil.copy(AGENT_JS, project / "dist" / "agent.js")
    (project / "gazua.yaml").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "typescript": {"module": "dist/agent.js", "entrypoint_export": "entrypoint"},
                "tools": {"search_docs": {"safe": True, "sensitive": False}},
                "canaries": ["GAZUA-CANARY-7f3a9c"],
            }
        ),
        encoding="utf-8",
    )
    (project / ".gitignore").write_text(".gazua/\n", encoding="utf-8")
    env = {**build_clean_environment(), "PYTHONIOENCODING": "utf-8"}
    ran = run_isolated(
        [python, "-m", "gazua", "run", "--agent", "--mold", "secret-04", "--max-runs", "2"],
        cwd=project,
        env=env,
    )
    assert ran.returncode == 1, ran.stdout + ran.stderr
    document = json.loads((project / ".gazua" / "run.json").read_text(encoding="utf-8"))
    assert document["target_adapter"] == "typescript"
    assert (
        document["typescript"]["sdk_version"]
        == json.loads((PACKAGE / "package.json").read_text(encoding="utf-8"))["version"]
    )
