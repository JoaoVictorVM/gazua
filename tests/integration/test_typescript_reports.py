import json
from pathlib import Path

import jsonschema
import pytest
from report_factory import document
from typescript_support import TypeScriptProject, require_typescript

from conftest import build_clean_environment
from gazua.reports.legacy_v5 import (
    build_run_v5_json_schema,
    packaged_run_v5_json_schema,
    render_run_v5_json_schema,
)
from gazua.reports.models import build_run_json_schema
from gazua.reports.rendering import render_report
from gazua.reports.storage import RunLoadError, document_json, parse_run_document


def test_run_v6_regenerates_offline_and_v5_still_loads(tmp_path: Path) -> None:
    require_typescript()
    project = TypeScriptProject(tmp_path / "project")
    (project.root / ".gitignore").write_text(".gazua/\n", encoding="utf-8")
    env = {**build_clean_environment(), "PYTHONIOENCODING": "utf-8"}

    result = project.cli("run", "--agent", "--mold", "secret-04", env=env)

    assert result.returncode == 1, result.stderr
    assert "TypeScript target: Node" in result.stdout
    content = (project.root / ".gazua" / "run.json").read_bytes()
    data = json.loads(content.decode("utf-8"))
    jsonschema.validate(data, build_run_json_schema())
    assert data["schema_version"] == 6
    assert data["target_adapter"] == "typescript"
    runtime = data["typescript"]
    assert set(runtime) == {"protocol_version", "sdk_version", "node_version", "module_sha256"}
    assert runtime["sdk_version"] == "0.1.0-dev.0"
    text = content.decode("utf-8")
    # No path, cwd or package manager detail reaches the document beyond the target reference.
    assert str(project.root) not in text
    assert str(project.root).replace("\\", "\\\\") not in text
    assert "node_modules" not in text

    # The report is rebuilt without Node on PATH: the command never starts it.
    empty = tmp_path / "no-node"
    empty.mkdir()
    offline = {**env, "PATH": str(empty)}
    regenerated = project.cli("report", "--from", ".gazua/run.json", env=offline)
    assert regenerated.returncode == 0, regenerated.stderr
    assert "TypeScript target: Node" in regenerated.stdout
    html, rendered = render_report(parse_run_document(content))
    assert "TypeScript target: Node" in html
    assert "TypeScript target" in rendered


def test_v5_document_adapts_without_typescript_provenance() -> None:
    assert packaged_run_v5_json_schema().replace("\r\n", "\n") == render_run_v5_json_schema()
    data = json.loads(document_json(document()))
    assert data["schema_version"] == 6
    assert data["typescript"] is None
    data["schema_version"] = 5
    data.pop("typescript")
    jsonschema.validate(data, build_run_v5_json_schema())

    adapted = parse_run_document(json.dumps(data).encode("utf-8"))

    assert adapted.schema_version == 6
    assert adapted.target_adapter == "python"
    assert adapted.typescript is None
    with pytest.raises(RunLoadError) as caught:
        parse_run_document(json.dumps({**data, "schema_version": 7}).encode("utf-8"))
    assert caught.value.code == "run_schema_version_unsupported"
    # A v5 document cannot claim a TypeScript target it could not describe.
    with pytest.raises(RunLoadError):
        parse_run_document(json.dumps({**data, "target_adapter": "typescript"}).encode("utf-8"))


def test_python_document_cannot_claim_typescript_provenance() -> None:
    data = json.loads(document_json(document()))
    data["typescript"] = {
        "protocol_version": 1,
        "sdk_version": "0.1.0",
        "node_version": "22.23.4",
        "module_sha256": "0" * 64,
    }
    with pytest.raises(RunLoadError):
        parse_run_document(json.dumps(data).encode("utf-8"))
    # Only agent mode reaches a TypeScript target, so a tools run cannot claim one either.
    assert data["metadata"]["mode"] == "tools"
    with pytest.raises(RunLoadError):
        parse_run_document(json.dumps({**data, "target_adapter": "typescript"}).encode("utf-8"))
