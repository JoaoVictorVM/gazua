import sys
from pathlib import Path
from typing import Any

import pytest
from mcp_support import McpProject, require_mcp

from gazua.mcp.models import McpError, McpLaunch, inventory_from, tool_from_definition


def launch(project: McpProject) -> McpLaunch:
    server = project.config["mcp"]
    return McpLaunch(sys.executable, tuple(server["args"]), project.root)


def tool(name: str) -> dict[str, Any]:
    return {"name": name, "inputSchema": {"type": "object"}}


@pytest.mark.parametrize(
    ("pages", "code"),
    [
        (
            [{"tools": [tool("a")], "next": "page-1"}, {"tools": [tool("a")]}],
            "mcp_inventory_invalid",
        ),
        (
            [{"tools": [tool("a")], "next": "page-1"}, {"tools": [tool("b")], "next": "page-1"}],
            "mcp_inventory_invalid",
        ),
        ([{"tools": [{"name": "", "inputSchema": {"type": "object"}}]}], "mcp_inventory_invalid"),
        ([{"tools": [{"name": "x", "inputSchema": "nope"}]}], "mcp_inventory_invalid"),
    ],
    ids=["duplicate", "cursor_cycle", "empty_name", "schema_not_object"],
)
def test_pagination_duplicates_and_cursor_cycles(
    tmp_path: Path, pages: list[dict[str, Any]], code: str
) -> None:
    require_mcp()
    from gazua.mcp.client import McpClient

    project = McpProject(tmp_path / "project")
    project.set_pages(pages)

    with McpClient(launch(project), timeout=20) as client, pytest.raises(McpError) as caught:
        client.list_inventory()

    assert caught.value.code == code


def test_every_page_is_read_and_order_does_not_change_the_digest(tmp_path: Path) -> None:
    require_mcp()
    from gazua.mcp.client import McpClient

    project = McpProject(tmp_path / "project")
    tools = [tool(f"t{index}") for index in range(5)]
    project.set_tools(tools, page_size=2)
    with McpClient(launch(project), timeout=20) as client:
        paged = client.list_inventory()
    project.set_tools(list(reversed(tools)))
    with McpClient(launch(project), timeout=20) as client:
        single = client.list_inventory()

    assert [item.name for item in paged.tools] == [f"t{index}" for index in range(5)]
    assert paged.digest == single.digest


def test_too_many_pages_is_a_limit(tmp_path: Path) -> None:
    require_mcp()
    from gazua.mcp.client import McpClient

    project = McpProject(tmp_path / "project")
    project.set_tools([tool(f"t{index}") for index in range(101)], page_size=1)

    with McpClient(launch(project), timeout=30) as client, pytest.raises(McpError) as caught:
        client.list_inventory()

    assert caught.value.code == "mcp_inventory_limit"


def test_oversized_message_is_refused_before_parsing(tmp_path: Path) -> None:
    require_mcp()
    from gazua.mcp.client import McpClient

    project = McpProject(tmp_path / "project")
    project.scenario["oversized_listing"] = True
    project.save_scenario()

    with McpClient(launch(project), timeout=20) as client, pytest.raises(McpError) as caught:
        client.list_inventory()

    assert caught.value.code in ("mcp_inventory_limit", "mcp_transport_lost")


def test_unsupported_protocol_revision_is_refused(tmp_path: Path) -> None:
    require_mcp()
    from gazua.mcp.client import McpClient

    project = McpProject(tmp_path / "project")
    project.scenario["protocol_version"] = "2024-11-05"
    project.save_scenario()

    with pytest.raises(McpError) as caught:
        McpClient(launch(project), timeout=20).start()

    assert caught.value.code in ("mcp_protocol_unsupported", "mcp_start_failed")


def test_server_that_exits_is_a_start_failure(tmp_path: Path) -> None:
    require_mcp()
    from gazua.mcp.client import McpClient

    project = McpProject(tmp_path / "project")
    project.scenario["exit_on_start"] = True
    project.save_scenario()

    with pytest.raises(McpError) as caught:
        McpClient(launch(project), timeout=20).start()

    assert caught.value.code == "mcp_start_failed"


def test_server_that_never_answers_times_out(tmp_path: Path) -> None:
    require_mcp()
    from gazua.mcp.client import McpClient

    project = McpProject(tmp_path / "project")
    project.scenario["sleep_on_start"] = 30
    project.save_scenario()

    with pytest.raises(McpError) as caught:
        McpClient(launch(project), timeout=1).start()

    assert caught.value.code == "mcp_start_timeout"


def test_digest_covers_every_definition_field() -> None:
    base = {"name": "a", "description": "x", "inputSchema": {"type": "object"}}
    first = tool_from_definition(base)
    for change in (
        {"description": "y"},
        {"inputSchema": {"type": "object", "properties": {"n": {"type": "string"}}}},
        {"outputSchema": {"type": "object"}},
        {"annotations": {"readOnlyHint": True}},
    ):
        assert tool_from_definition({**base, **change}).digest != first.digest
    with pytest.raises(McpError):
        inventory_from("2025-06-18", [first, first])
