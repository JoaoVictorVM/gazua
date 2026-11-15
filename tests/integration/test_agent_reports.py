import json
from pathlib import Path
from typing import Any

import pytest

from gazua.modes.agent_models import NOT_REPORTED_TEXT
from gazua.reports.rendering import render_report, terminal_lines
from gazua.reports.storage import RunLoadError, parse_run_document

EXAMPLE = Path(__file__).resolve().parents[1] / "support" / "run-example.json"


def test_old_run_documents_and_tools_are_unchanged(tools_project: Any) -> None:
    content = EXAMPLE.read_bytes()
    legacy = parse_run_document(content)
    assert legacy.legitimate_use is None
    assert legacy.engine.stop_reason is None
    html, markdown = render_report(legacy)
    assert "Legitimate use" not in html
    assert "Legitimate use" not in markdown
    assert not any("Legitimate use" in line for line in terminal_lines(legacy))

    # An agent document from before the measurement existed says so; it is never 100%.
    data = json.loads(content)
    data["metadata"]["mode"] = "agent"
    agent_legacy = parse_run_document(json.dumps(data).encode("utf-8"))
    assert NOT_REPORTED_TEXT in terminal_lines(agent_legacy)

    # Tools mode never carries legitimate use, and runs no task or stop policy.
    data = json.loads(content)
    data["legitimate_use"] = {
        "planned": 0,
        "evaluated": 0,
        "succeeded": 0,
        "failed": 0,
        "not_tested": 0,
        "rate": None,
        "coverage": "not_tested",
        "tasks": [],
    }
    with pytest.raises(RunLoadError):
        parse_run_document(json.dumps(data).encode("utf-8"))

    tools_project.write(legit_tasks=[{"request": "Show my order", "expected_tool": "get_order"}])
    result = tools_project.run(mold="idor-01")
    keys = {record.request_key for record in result.engine.records}
    assert not any(key.startswith("legitimate:") for key in keys)
    assert result.engine.stop_reason is None
    assert "entrypoint_called" not in {item["kind"] for item in tools_project.effects()}
