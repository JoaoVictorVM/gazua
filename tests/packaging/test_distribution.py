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
SCHEMA_PATH = "src/gazua/schemas/config-v1.schema.json"
MOLD_SCHEMA_PATH = "src/gazua/schemas/mold-v1.schema.json"
INTEGRATION_SCHEMAS = ("session-v1.schema.json", "call-record-v1.schema.json")
EXECUTION_SCHEMAS = (
    "session-v2.schema.json",
    "execution-v1.schema.json",
    "receiver-hit-v1.schema.json",
)
VERDICT_SCHEMAS = ("attack-result-v1.schema.json", "effect-observation-v1.schema.json")
BUILTIN_PATH = "gazua/catalog/builtin/"
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
    assert {
        "LICENSE",
        "README.md",
        "SECURITY.md",
        "docs/configuration.md",
        "docs/execution.md",
        "docs/integration.md",
        "docs/molds.md",
        "docs/releasing.md",
        "docs/tools-mode.md",
        "docs/verdicts.md",
        SCHEMA_PATH,
        MOLD_SCHEMA_PATH,
    } <= set(sdist_files)
    assert "gazua/schemas/config-v1.schema.json" in wheel_files
    assert wheel_files["gazua/schemas/config-v1.schema.json"] == sdist_files[SCHEMA_PATH]


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


def test_installed_init_and_schema_work_outside_checkout(
    distributions: Path, tmp_path: Path, run_isolated
) -> None:
    environment = tmp_path / "environment"
    created = run_isolated(["uv", "venv", "--python", sys.executable, environment], cwd=tmp_path)
    assert created.returncode == 0, created.stderr
    python = interpreter_of(environment)
    installed = run_isolated(
        ["uv", "pip", "install", "--python", python, wheel_in(distributions)], cwd=tmp_path
    )
    assert installed.returncode == 0, installed.stderr
    project = tmp_path / "project"
    project.mkdir()
    (project / "agent.py").write_text(
        "import gazua\n@gazua.tool\ndef refund_order(): ...\n", encoding="utf-8"
    )

    result = run_isolated([scripts_folder(environment) / "gazua", "init"], cwd=project)

    assert result.returncode == 0, result.stderr
    assert "refund_order: sensitive" in result.stdout
    assert (project / ".gitignore").read_text(encoding="utf-8") == ".gazua/\n"

    probe = (
        "import json\n"
        "from gazua.config import load_config\n"
        "from gazua.config.models import packaged_json_schema, render_json_schema\n"
        "assert json.loads(packaged_json_schema()) == json.loads(render_json_schema())\n"
        "print(load_config('gazua.yaml').config.tools['refund_order'].sensitive)\n"
    )
    loaded = run_isolated([python, "-c", probe], cwd=project)
    assert loaded.returncode == 0, loaded.stderr
    assert loaded.stdout.strip() == "True"


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


def test_catalog_and_schemas_work_in_installed_wheel_and_sdist(
    distributions: Path, project_root: Path, tmp_path: Path, run_isolated
) -> None:
    wheel_files = wheel_entries(wheel_in(distributions))
    sdist_files = sdist_entries(sdist_in(distributions))
    packaged = {name for name in wheel_files if name.startswith(BUILTIN_PATH)}
    source = project_root / "src" / BUILTIN_PATH
    expected = {f"{BUILTIN_PATH}{path.name}" for path in source.iterdir() if path.is_file()}
    assert packaged == expected
    assert len([name for name in packaged if name.endswith(".yaml")]) == 60
    for name in packaged:
        assert wheel_files[name] == sdist_files[f"src/{name}"]
    assert wheel_files["gazua/schemas/mold-v1.schema.json"] == sdist_files[MOLD_SCHEMA_PATH]

    environment = tmp_path / "environment"
    created = run_isolated(["uv", "venv", "--python", sys.executable, environment], cwd=tmp_path)
    assert created.returncode == 0, created.stderr
    python = interpreter_of(environment)
    installed = run_isolated(
        ["uv", "pip", "install", "--python", python, wheel_in(distributions)], cwd=tmp_path
    )
    assert installed.returncode == 0, installed.stderr
    workdir = tmp_path / "work"
    workdir.mkdir()

    listing = run_isolated([scripts_folder(environment) / "gazua", "run", "--list"], cwd=workdir)

    assert listing.returncode == 0, listing.stderr
    assert listing.stdout.startswith("Attack catalog v0.1: 15 molds")
    assert "No configuration loaded" in listing.stdout
    assert list(workdir.iterdir()) == []

    probe = "\n".join(
        [
            "import json",
            "from gazua.catalog import RELEASES, load_catalog",
            "from gazua.catalog.models import packaged_mold_json_schema as packaged",
            "from gazua.catalog.models import render_mold_json_schema as rendered",
            "assert json.loads(packaged()) == json.loads(rendered())",
            "results = [load_catalog(release=release) for release in RELEASES]",
            "assert not any(result.has_errors for result in results)",
            "print([len(result.entries) for result in results])",
        ]
    )
    loaded = run_isolated([python, "-c", probe], cwd=workdir)
    assert loaded.returncode == 0, loaded.stderr
    assert loaded.stdout.strip() == "[15, 30, 60]"


def test_integration_schemas_and_guide_ship_in_wheel_and_sdist(
    distributions: Path, tmp_path: Path, run_isolated
) -> None:
    wheel_files = wheel_entries(wheel_in(distributions))
    sdist_files = sdist_entries(sdist_in(distributions))
    for name in INTEGRATION_SCHEMAS:
        assert wheel_files[f"gazua/schemas/{name}"] == sdist_files[f"src/gazua/schemas/{name}"]
    assert "docs/integration.md" in sdist_files

    environment = tmp_path / "environment"
    created = run_isolated(["uv", "venv", "--python", sys.executable, environment], cwd=tmp_path)
    assert created.returncode == 0, created.stderr
    python = interpreter_of(environment)
    installed = run_isolated(
        ["uv", "pip", "install", "--python", python, wheel_in(distributions)], cwd=tmp_path
    )
    assert installed.returncode == 0, installed.stderr
    workdir = tmp_path / "work"
    workdir.mkdir()

    probe = "\n".join(
        [
            "import json, sys",
            "import gazua",
            "assert not {'pydantic', 'typer', 'yaml', 'jinja2'} & set(sys.modules)",
            "from gazua.runtime.session_models import (",
            "    packaged_schema, render_call_record_json_schema, render_session_json_schema)",
            "assert packaged_schema('session-v1.schema.json') == render_session_json_schema()",
            "assert packaged_schema('call-record-v1.schema.json') == "
            "render_call_record_json_schema()",
            "def read_note(name): return 'note ' + name",
            "tools = [read_note]",
            "assert gazua.wrap(tools) is tools",
            "print(gazua.wrap(tools)[0]('a'))",
        ]
    )
    result = run_isolated([python, "-c", probe], cwd=workdir)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "note a"
    assert list(workdir.iterdir()) == []


def test_execution_schemas_and_guide_ship_in_distributions(
    distributions: Path, tmp_path: Path, run_isolated
) -> None:
    wheel_files = wheel_entries(wheel_in(distributions))
    sdist_files = sdist_entries(sdist_in(distributions))
    for name in (*INTEGRATION_SCHEMAS, *EXECUTION_SCHEMAS):
        assert wheel_files[f"gazua/schemas/{name}"] == sdist_files[f"src/gazua/schemas/{name}"]
    assert "docs/execution.md" in sdist_files
    assert "gazua/runtime/worker.py" in wheel_files

    environment = tmp_path / "environment"
    created = run_isolated(["uv", "venv", "--python", sys.executable, environment], cwd=tmp_path)
    assert created.returncode == 0, created.stderr
    python = interpreter_of(environment)
    installed = run_isolated(
        ["uv", "pip", "install", "--python", python, wheel_in(distributions)], cwd=tmp_path
    )
    assert installed.returncode == 0, installed.stderr
    workdir = tmp_path / "work"
    workdir.mkdir()
    (workdir / "agent.py").write_text(
        "def entrypoint(message):\n    return 'echo ' + message\n", encoding="utf-8"
    )
    (workdir / "consumer.py").write_text(
        "from gazua.runtime import call_entrypoint\n"
        "def execute(request, context):\n"
        "    return {'output': call_entrypoint(context.entrypoint, 'hi')}\n",
        encoding="utf-8",
    )

    probe = "\n".join(
        [
            "import json, sys",
            "import gazua",
            "assert not {'pydantic', 'typer', 'yaml', 'jinja2'} & set(sys.modules)",
            "assert gazua.report_usage(cost_usd=0.1) is False",
            "from pathlib import Path",
            "from gazua.config.models import GazuaConfig",
            "from gazua.runtime import ExecutionRequest, execute_plan, prepare_run",
            "from gazua.runtime.run_models import (",
            "    render_execution_json_schema, render_receiver_hit_json_schema)",
            "from gazua.runtime.session_models import (",
            "    packaged_schema, render_session_v2_json_schema)",
            "assert packaged_schema('execution-v1.schema.json') == render_execution_json_schema()",
            "assert packaged_schema('receiver-hit-v1.schema.json') == "
            "render_receiver_hit_json_schema()",
            "assert packaged_schema('session-v2.schema.json') == render_session_v2_json_schema()",
            "config = GazuaConfig.model_validate(",
            "    {'schema_version': 1, 'entrypoint': 'agent:entrypoint'})",
            "request = ExecutionRequest.model_validate({'key': 'k-1', 'mold_id': 'k',",
            "    'repetition': 1, 'mode': 'agent', 'executor': 'consumer:execute',",
            "    'payload': {}, 'requires_receiver': False, 'receiver_transport': False,",
            "    'usage_reporting': False})",
            "summary = execute_plan(prepare_run(config, [request], project_root=Path('.')))",
            "print(summary.records[0].status)",
        ]
    )
    result = run_isolated([python, "-c", probe], cwd=workdir)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "completed"


def test_verdict_contracts_and_guide_are_packaged(
    distributions: Path, project_root: Path, tmp_path: Path, run_isolated
) -> None:
    wheel_files = wheel_entries(wheel_in(distributions))
    sdist_files = sdist_entries(sdist_in(distributions))
    for name in VERDICT_SCHEMAS:
        assert wheel_files[f"gazua/schemas/{name}"] == sdist_files[f"src/gazua/schemas/{name}"]
    assert "docs/verdicts.md" in sdist_files
    assert "gazua/verdicts/engine.py" in wheel_files

    copy = tmp_path / "checkout"
    schemas = copy / "src/gazua/schemas"
    shutil.copytree(project_root / "src/gazua/schemas", schemas)
    script = copy / ".github/scripts/generate_verdict_schemas.py"
    script.parent.mkdir(parents=True)
    shutil.copy(project_root / ".github/scripts/generate_verdict_schemas.py", script)
    for name in VERDICT_SCHEMAS:
        (schemas / name).unlink()
    earlier = {path.name: path.read_bytes() for path in schemas.iterdir()}
    generated = run_isolated(
        [sys.executable, script], cwd=copy, env={**os.environ, "PYTHONPATH": ""}
    )
    assert generated.returncode == 0, generated.stderr
    for name, content in earlier.items():
        assert (schemas / name).read_bytes() == content
    for name in VERDICT_SCHEMAS:
        fresh = (schemas / name).read_bytes()
        published = (project_root / "src/gazua/schemas" / name).read_bytes()
        assert fresh == published.replace(b"\r\n", b"\n")
        assert fresh == wheel_files[f"gazua/schemas/{name}"].replace(b"\r\n", b"\n")

    environment = tmp_path / "environment"
    created = run_isolated(["uv", "venv", "--python", sys.executable, environment], cwd=tmp_path)
    assert created.returncode == 0, created.stderr
    python = interpreter_of(environment)
    installed = run_isolated(
        ["uv", "pip", "install", "--python", python, wheel_in(distributions)], cwd=tmp_path
    )
    assert installed.returncode == 0, installed.stderr
    workdir = tmp_path / "work"
    workdir.mkdir()
    probe = "\n".join(
        [
            "import sys",
            "import gazua",
            "assert not any('verdicts' in name for name in sys.modules)",
            "from gazua.runtime.session_models import packaged_schema",
            "from gazua.verdicts.models import (",
            "    render_attack_result_json_schema, render_effect_observation_json_schema)",
            "from gazua.verdicts import upper_bound",
            "assert packaged_schema('attack-result-v1.schema.json') == "
            "render_attack_result_json_schema()",
            "assert packaged_schema('effect-observation-v1.schema.json') == "
            "render_effect_observation_json_schema()",
            "print(round(upper_bound(0, 5), 4))",
        ]
    )
    result = run_isolated([python, "-c", probe], cwd=workdir)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "0.4507"


def test_tools_mode_guide_is_distributed(distributions: Path) -> None:
    wheel_files = wheel_entries(wheel_in(distributions))
    sdist_files = sdist_entries(sdist_in(distributions))

    assert "docs/tools-mode.md" in sdist_files
    for module in ("__init__", "tools", "tools_models", "tools_plan", "tools_executor"):
        assert f"gazua/modes/{module}.py" in wheel_files
        assert f"src/gazua/modes/{module}.py" in sdist_files
    assert "gazua/modes/tools_presentation.py" in wheel_files
    for name in [*wheel_files, *sdist_files]:
        assert not FORBIDDEN_PARTS & set(Path(name).parts)


REPORT_FILES = (
    "reports/__init__.py",
    "reports/builder.py",
    "reports/capture.py",
    "reports/fixes.py",
    "reports/lifecycle.py",
    "reports/models.py",
    "reports/redaction.py",
    "reports/rendering.py",
    "reports/storage.py",
    "reports/terminal.py",
    "reports/templates/report.html.j2",
    "reports/templates/report.md.j2",
    "reports/assets/report.css",
    "reports/assets/report.js",
    "schemas/run-v1.schema.json",
)


def test_report_assets_schema_and_guide_are_distributed(
    distributions: Path, project_root: Path, tmp_path: Path, run_isolated
) -> None:
    wheel_files = wheel_entries(wheel_in(distributions))
    sdist_files = sdist_entries(sdist_in(distributions))
    for name in REPORT_FILES:
        assert wheel_files[f"gazua/{name}"].replace(b"\r\n", b"\n") == sdist_files[
            f"src/gazua/{name}"
        ].replace(b"\r\n", b"\n")
    assert "docs/reports.md" in sdist_files
    for name in [*wheel_files, *sdist_files]:
        assert not FORBIDDEN_PARTS & set(Path(name).parts)

    copy = tmp_path / "checkout"
    schemas = copy / "src/gazua/schemas"
    shutil.copytree(project_root / "src/gazua/schemas", schemas)
    script = copy / ".github/scripts/generate_report_schema.py"
    script.parent.mkdir(parents=True)
    shutil.copy(project_root / ".github/scripts/generate_report_schema.py", script)
    (schemas / "run-v1.schema.json").unlink()
    earlier = {path.name: path.read_bytes() for path in schemas.iterdir()}
    generated = run_isolated(
        [sys.executable, script], cwd=copy, env={**os.environ, "PYTHONPATH": ""}
    )
    assert generated.returncode == 0, generated.stderr
    for name, content in earlier.items():
        assert (schemas / name).read_bytes() == content
    published = (project_root / "src/gazua/schemas/run-v1.schema.json").read_bytes()
    assert (schemas / "run-v1.schema.json").read_bytes() == published.replace(b"\r\n", b"\n")

    environment = tmp_path / "environment"
    created = run_isolated(["uv", "venv", "--python", sys.executable, environment], cwd=tmp_path)
    assert created.returncode == 0, created.stderr
    python = interpreter_of(environment)
    installed = run_isolated(
        ["uv", "pip", "install", "--python", python, wheel_in(distributions)], cwd=tmp_path
    )
    assert installed.returncode == 0, installed.stderr
    workdir = tmp_path / "work"
    workdir.mkdir()
    shutil.copy(project_root / "tests/support/run-example.json", workdir / "run.json")
    rendered = run_isolated(
        [python, "-m", "gazua", "report", "--from", "run.json"],
        cwd=workdir,
    )
    assert rendered.returncode == 0, rendered.stderr
    html = (workdir / ".gazua" / "report.html").read_text(encoding="utf-8")
    assert "Content-Security-Policy" in html
    assert 'id="fix-idor_via_agent"' in html
    probe = "\n".join(
        [
            "import sys",
            "import gazua",
            "assert not any(name.startswith('gazua.reports') for name in sys.modules)",
            "from gazua.reports.models import packaged_run_json_schema, render_run_json_schema",
            "assert packaged_run_json_schema().splitlines() == "
            "render_run_json_schema().splitlines()",
            "print('ok')",
        ]
    )
    result = run_isolated([python, "-c", probe], cwd=workdir)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"
