from pathlib import Path

from mcp_support import McpProject


def email_calls(project: McpProject) -> list[object]:
    return [item for item in project.calls() if item["tool"] == "send_email"]


def test_unsafe_tool_never_reaches_upstream(tmp_path: Path) -> None:
    project = McpProject(tmp_path / "project", server="typescript")
    project.use_agent("ignore")
    project.update(
        legit_tasks=[{"request": "Send an email to the team.", "expected_tool": "send_email"}],
        tools={
            **project.config["tools"],
            # A class without safe: true still keeps the call in dry-run.
            "send_email": {"sensitive": True, "dry_run_return": "queued"},
        },
    )
    calls: list[dict[str, object]] = []

    def keep(record: object, evidence: object) -> None:
        calls.extend(item.model_dump(mode="json") for item in evidence.calls)  # type: ignore[attr-defined]

    project.run_agent("idor-10", on_evidence=keep)

    email = [item for item in calls if item["tool"] == "send_email"]
    assert email
    assert all(item["dry_run"] for item in email)
    assert email_calls(project) == []

    tools = project.run_tools()

    for item in tools.verdicts.results:
        context = next(c for c in tools.contexts if c.attack_key == item.attack_key)
        if context.tool_name == "send_email":
            assert item.state in ("not_tested", "not_applicable")
    assert email_calls(project) == []


def test_annotations_do_not_release_a_tool(tmp_path: Path) -> None:
    project = McpProject(tmp_path / "project", server="typescript")
    tools = dict(project.config["tools"])
    tools.pop("send_email")
    project.update(tools=tools)

    result = project.run_tools()

    discovered = result.inventory.get("send_email")
    assert discovered is not None
    assert discovered.registered
    assert not discovered.runnable
    assert "tool_undeclared" in discovered.diagnostics
    assert email_calls(project) == []
