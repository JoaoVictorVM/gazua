from pathlib import Path

import pytest
from mcp_support import McpProject

from gazua.catalog.loader import load_catalog
from gazua.catalog.selection import adapter_pending
from gazua.config.models import GazuaConfig
from gazua.modes.agent_plan import agent_molds, entry_reachable, plan_agent
from gazua.modes.tools_models import ToolsInventory

DESCRIPTION_MOLDS = ("idor-10", "memory-08", "output-09", "permission-11", "secret-11")


def mcp_config(entry: bool = True) -> GazuaConfig:
    document = {
        "schema_version": 1,
        "entrypoint": "mcp_agent:entrypoint",
        "mcp": {"transport": "stdio", "command": "server"},
        "tools": {"search_docs": {"safe": True, "sensitive": False}},
    }
    if entry:
        document["agent_entries"] = {
            "mcp_tool_description": {"tool": "search_docs", "request": "Check it."}
        }
    return GazuaConfig.model_validate(document)


def test_all_five_description_molds_selectable() -> None:
    config = mcp_config()
    molds = agent_molds(load_catalog(config, release="v0.4").entries)
    chosen = [mold for mold in molds if mold.entry == "mcp_tool_description"]

    assert sorted(mold.id for mold in chosen) == list(DESCRIPTION_MOLDS)
    for mold_id in DESCRIPTION_MOLDS:
        [exact] = agent_molds(load_catalog(config, release="v0.4").entries, mold_id)
        assert entry_reachable(config, exact)
    plan = plan_agent(chosen, config, ToolsInventory(complete=True), repetitions=1)
    for scenario in plan.scenarios:
        assert scenario.context.capabilities.entry_supported is True
        assert all(not request.injections for request in scenario.requests)

    python = GazuaConfig.model_validate({**config.to_document(), "mcp": None, "agent_entries": {}})
    for mold in chosen:
        assert adapter_pending(mold)
        assert not entry_reachable(python, mold)
        assert not entry_reachable(mcp_config(entry=False), mold)


@pytest.mark.parametrize("mold_id", ["memory-08", "output-09", "secret-11"])
def test_description_molds_without_a_signal_channel_are_not_tested(
    tmp_path: Path, mold_id: str
) -> None:
    project = McpProject(tmp_path / "project")
    project.use_agent("follow")
    project.update(
        agent_entries={
            "mcp_tool_description": {"tool": "search_docs", "request": "Check my order."}
        }
    )

    result = project.run_agent(mold_id, repetitions=1)

    for item in result.verdicts.results:
        assert item.state in ("not_tested", "resisted", "conditional_risk")
