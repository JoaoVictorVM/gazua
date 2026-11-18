from pathlib import Path

from mcp_support import McpProject
from verify_support import accepted, baseline_document, gazua, latest_run


def test_verify_uses_adapter_and_refuses_changed_snapshot(tmp_path: Path) -> None:
    project = McpProject(tmp_path / "project")
    entry = accepted(project.root, "--tools", "--mold", "idor-01")
    project.harden()
    project.clear_calls()

    verified = gazua(project.root, "verify", "idor-01", "--mode", "tools")

    assert verified.returncode == 0, verified.stdout + verified.stderr
    assert "closed" in verified.stdout
    reads = [item for item in project.calls() if item["tool"] == "get_order"]
    assert len(reads) == 20 * len(entry["scenarios"])
    run = latest_run(project.root)
    assert run["target_adapter"] == "mcp_stdio"
    assert run["mcp"]["inventory_hash"]
    [closed] = baseline_document(project.root)["entries"]
    assert closed["status"] == "closed"


def test_changed_server_cannot_close_a_finding(tmp_path: Path) -> None:
    project = McpProject(tmp_path / "project")
    accepted(project.root, "--tools", "--mold", "idor-01")
    project.harden()
    tools = [
        {
            "name": "get_order",
            "description": "Reads one order by id, with its history.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "order_id": {"type": "string"},
                    "actor_id": {"type": "string"},
                    "owner_id": {"type": "string"},
                },
                "required": ["order_id", "actor_id"],
            },
        },
        {"name": "send_email", "inputSchema": {"type": "object"}},
    ]
    project.set_tools(tools)

    verified = gazua(project.root, "verify", "idor-01", "--mode", "tools")

    assert verified.returncode == 2, verified.stdout + verified.stderr
    assert "cannot close" in verified.stderr
    [entry] = baseline_document(project.root)["entries"]
    assert entry["status"] == "open"
    assert latest_run(project.root)["verification"]["outcome"] == "incomplete"
