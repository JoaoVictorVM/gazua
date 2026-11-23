import json
import os
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

HTTP_FILES = (
    "http/__init__.py",
    "http/authorization.py",
    "http/client.py",
    "http/executor.py",
    "http/models.py",
    "http/policy.py",
    "otel/__init__.py",
    "otel/decoder.py",
    "otel/evidence.py",
    "otel/models.py",
    "otel/receiver.py",
    "reports/legacy_v4.py",
    "schemas/http-authorization-v1.schema.json",
    "schemas/http-trace-evidence-v1.schema.json",
    "schemas/run-v5.schema.json",
)
CONFIG = {
    "schema_version": 1,
    "http": {"endpoint": "http://127.0.0.1:9/agent", "real_side_effects": "i_understand"},
    "traces": {"transport": "otlp_http"},
    "tools": {},
}
AUTHORIZE = (
    "from pathlib import Path; "
    "from gazua.config.loader import load_config; "
    "from gazua.http.authorization import new_receipt, write_receipt; "
    "write_receipt(Path('.'), new_receipt(load_config('gazua.yaml').config))"
)


@pytest.fixture(scope="module")
def built(project_root: Path, tmp_path_factory: pytest.TempPathFactory, run_isolated) -> Path:
    supplied = os.environ.get("GAZUA_DIST_DIR")
    if supplied:
        return (project_root / supplied).resolve()
    output = tmp_path_factory.mktemp("otel-dist")
    result = run_isolated(["uv", "build", "--out-dir", output], cwd=project_root)
    assert result.returncode == 0, result.stderr
    return output


def _environment(built: Path, factory: pytest.TempPathFactory, run_isolated, spec: str) -> Path:
    environment = factory.mktemp("otel-env") / "environment"
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
    return _environment(built, tmp_path_factory, run_isolated, "gazua[otel] @ {wheel}")


def test_wheel_and_sdist_carry_the_adapters_and_their_docs(built: Path) -> None:
    with zipfile.ZipFile(next(built.glob("*.whl"))) as archive:
        wheel_files = set(archive.namelist())
        metadata = next(
            archive.read(name).decode("utf-8")
            for name in wheel_files
            if name.endswith(".dist-info/METADATA")
        )
    with tarfile.open(next(built.glob("*.tar.gz"))) as archive:
        sdist_files = {name.split("/", 1)[1] for name in archive.getnames() if "/" in name}

    for name in HTTP_FILES:
        assert f"gazua/{name}" in wheel_files, name
        assert f"src/gazua/{name}" in sdist_files, name
    assert "docs/http.md" in sdist_files
    assert "docs/traces.md" in sdist_files
    assert "Provides-Extra: otel" in metadata
    assert "opentelemetry-proto" in metadata
    requires = [line for line in metadata.splitlines() if line.startswith("Requires-Dist:")]
    assert all("extra ==" in line for line in requires if "opentelemetry" in line)


def test_base_install_is_light_and_otel_extra_decodes_otlp(
    base: Path, extra: Path, tmp_path: Path, run_isolated
) -> None:
    light = run_isolated(
        [
            base,
            "-c",
            "import sys, gazua.cli, gazua.http, gazua.http.policy, gazua.otel, "
            "gazua.otel.models; "
            "assert not any(name.startswith(('opentelemetry', 'google.protobuf')) "
            "for name in sys.modules); "
            "assert not gazua.otel.extra_available()",
        ],
        cwd=tmp_path,
    )
    assert light.returncode == 0, light.stderr
    (tmp_path / "gazua.yaml").write_text(json.dumps(CONFIG), encoding="utf-8")
    authorized = run_isolated([base, "-c", AUTHORIZE], cwd=tmp_path)
    assert authorized.returncode == 0, authorized.stderr

    refused = run_isolated([base, "-m", "gazua", "run", "--agent"], cwd=tmp_path)

    assert refused.returncode == 2
    assert "Install gazua[otel]" in refused.stderr

    decoded = run_isolated(
        [
            extra,
            "-c",
            "import gazua.otel; from gazua.otel.decoder import decode_batch, empty_response; "
            "assert gazua.otel.extra_available(); "
            "assert decode_batch(b'', expected_run='r').spans == []; "
            "assert empty_response() == b''",
        ],
        cwd=tmp_path,
    )
    assert decoded.returncode == 0, decoded.stderr
