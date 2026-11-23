import json
from pathlib import Path

import jsonschema
import pytest
from mcp_support import McpProject
from report_factory import document

from gazua.reports.legacy_v3 import (
    build_run_v3_json_schema,
    packaged_run_v3_json_schema,
    render_run_v3_json_schema,
)
from gazua.reports.models import build_run_json_schema
from gazua.reports.rendering import render_report
from gazua.reports.storage import RunLoadError, document_json, parse_run_document

ROOT = Path(__file__).resolve().parents[2]


def test_run_v4_regenerates_and_legacy_v1_v3_still_load(tmp_path: Path) -> None:
    project = McpProject(tmp_path / "project")
    project.use_agent("follow")
    project.update(
        agent_entries={
            "mcp_tool_description": {"tool": "search_docs", "request": "Check my order status."}
        }
    )

    result = project.cli("run", "--agent", "--mold", "idor-10")

    assert result.returncode == 1, result.stderr
    assert "Poisoned descriptions delivered" in result.stdout
    content = (project.root / ".gazua" / "run.json").read_bytes()
    data = json.loads(content.decode("utf-8"))
    jsonschema.validate(data, build_run_json_schema())
    assert data["schema_version"] == 5
    assert data["target_adapter"] == "mcp_stdio"
    mcp = data["mcp"]
    assert sorted(mcp["tools"]) == ["get_order", "search_docs", "send_email"]
    assert all(item["delivered_turns"] == item["expected_turns"] for item in mcp["deliveries"])
    text = content.decode("utf-8")
    assert "scenario.json" not in text
    assert "mcp_raw_server" not in text
    assert "GAZUA_MCP_BROKER" not in text
    # Reports rebuild from the document alone, after the private folders are gone.
    loaded = parse_run_document(content)
    html, markdown = render_report(loaded)
    assert "MCP target over stdio" in markdown
    assert "MCP target over stdio" in html

    for example in ("run-example.json", "run-example-v2.json"):
        adapted = parse_run_document((ROOT / "tests" / "support" / example).read_bytes())
        assert adapted.target_adapter == "python"
        assert adapted.mcp is None


def test_v3_document_adapts_as_a_python_target() -> None:
    assert packaged_run_v3_json_schema().replace("\r\n", "\n") == render_run_v3_json_schema()
    data = json.loads(document_json(document()))
    data["schema_version"] = 3
    data.pop("target_adapter")
    data.pop("mcp")
    data.pop("http")
    jsonschema.validate(data, build_run_v3_json_schema())

    adapted = parse_run_document(json.dumps(data).encode("utf-8"))

    assert adapted.schema_version == 5
    assert adapted.target_adapter == "python"
    assert adapted.mcp is None
    assert adapted.http is None
    with pytest.raises(RunLoadError) as caught:
        parse_run_document(json.dumps({**data, "schema_version": 6}).encode("utf-8"))
    assert caught.value.code == "run_schema_version_unsupported"


def test_python_document_cannot_claim_mcp_provenance() -> None:
    data = json.loads(document_json(document()))
    data["mcp"] = {"protocol_version": "2025-06-18", "inventory_hash": "0" * 64}

    with pytest.raises(RunLoadError):
        parse_run_document(json.dumps(data).encode("utf-8"))
