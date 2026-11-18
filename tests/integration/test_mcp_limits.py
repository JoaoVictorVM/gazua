from pathlib import Path

import pytest
from mcp_support import McpProject

from gazua.diagnostics import ConfigError


def test_call_ceiling_and_message_limits(tmp_path: Path) -> None:
    project = McpProject(tmp_path / "project")
    project.use_agent("follow")
    project.update(
        agent_entries={
            "mcp_tool_description": {"tool": "search_docs", "request": "Check my order."}
        },
    )

    result = project.run_agent("idor-10", repetitions=1, overrides={"max_tool_calls": 1})

    # The simulated agent makes two calls per turn; the ceiling admits only the first, and the
    # attempt may be stopped before even that one reaches the server.
    assert len(project.calls()) <= 1
    [record] = result.engine.records
    assert record.status == "killed_at_ceiling"

    project.scenario["oversized_listing"] = True
    project.save_scenario()
    with pytest.raises(ConfigError) as caught:
        project.run_tools("idor-01")
    assert caught.value.diagnostics[0].code in ("mcp_inventory_limit", "mcp_transport_lost")
