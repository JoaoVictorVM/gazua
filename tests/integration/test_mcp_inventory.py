from pathlib import Path
from typing import Any

from mcp_support import McpProject


def test_new_unclassified_tool_is_dry_run_and_warns(tmp_path: Path) -> None:
    project = McpProject(tmp_path / "project", server="typescript")
    project.flag("new_tool")
    project.use_agent("ignore")
    project.update(
        legit_tasks=[{"request": "Export my data.", "expected_tool": "search_docs"}],
    )
    shown: list[Any] = []

    result = project.run_agent("idor-10", on_preview=shown.append)

    found = result.inventory.get("export_data")
    assert found is not None
    assert found.registered
    assert not found.runnable
    assert "tool_undeclared" in found.diagnostics
    assert [item["tool"] for item in project.calls() if item["tool"] == "export_data"] == []


def test_permissive_declaration_before_the_snapshot_stays_dry_run(tmp_path: Path) -> None:
    project = McpProject(tmp_path / "project", server="typescript")
    project.use_agent("ignore")
    project.update(
        tools={**project.config["tools"], "export_data": {"safe": True, "sensitive": False}},
        legit_tasks=[{"request": "Export my data.", "expected_tool": "search_docs"}],
    )
    logged: list[dict[str, Any]] = []

    def appear(preview: Any) -> None:
        # The tool appears after planning approved the snapshot.
        project.flag("new_tool")

    def keep(record: Any, evidence: Any) -> None:
        logged.extend(item.model_dump(mode="json") for item in evidence.calls)

    project.run_agent("idor-10", on_preview=appear, on_evidence=keep)

    exports = [item for item in logged if item["tool"] == "export_data"]
    assert exports
    assert all(item["dry_run"] for item in exports)
    assert [item for item in project.calls() if item["tool"] == "export_data"] == []


def test_changed_tool_stops_only_dependent_slots(tmp_path: Path) -> None:
    project = McpProject(tmp_path / "project", server="typescript")

    def change(preview: Any) -> None:
        project.flag("changed")

    result = project.run_tools(on_preview=change)

    assert result.exit_code == 2
    assert "mcp_tool_changed" in [item.code for item in result.diagnostics]
    changed = [record for record in result.engine.records if record.reason == "mcp_tool_changed"]
    assert changed
    by_key = {context.attack_key: context for context in result.contexts}
    for item in result.verdicts.results:
        if by_key[item.attack_key].tool_name == "get_order":
            assert item.state != "finding"
            assert item.state != "resisted"
    # Nothing reached get_order after its definition changed.
    assert [item for item in project.calls() if item["tool"] == "get_order"] == []
    independent = [record for record in result.engine.records if record.status == "completed"]
    assert independent


def test_silent_change_is_seen_before_call(tmp_path: Path) -> None:
    project = McpProject(tmp_path / "project")
    replaced = [
        {
            "name": "get_order",
            "description": "Reads one order by id.",
            "inputSchema": {
                "type": "object",
                "properties": {"order_id": {"type": "string"}, "actor_id": {"type": "string"}},
                "required": ["order_id"],
            },
        }
    ]

    def change(preview: Any) -> None:
        # No notification: only listing again before the call can notice this.
        project.set_tools(replaced)

    result = project.run_tools("idor-01", on_preview=change)

    assert result.exit_code == 2
    [item] = result.verdicts.results
    assert item.state == "not_tested"
    assert project.calls() == []
