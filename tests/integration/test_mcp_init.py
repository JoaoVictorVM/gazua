import json
from pathlib import Path

import pytest
from mcp_support import McpProject, require_typescript

from gazua.config.loader import load_config


def test_init_discovers_all_pages_without_tool_calls(tmp_path: Path) -> None:
    node = require_typescript()
    root = tmp_path / "project"
    root.mkdir()
    project = McpProject(tmp_path / "state-holder", server="typescript")
    (root / "gazua.yaml").unlink(missing_ok=True)

    result = project.cli(
        "init",
        str(root),
        "--mcp",
        node,
        "--mcp-arg",
        str(Path(project.config["mcp"]["args"][0])),
        "--mcp-arg",
        str(project.state),
    )

    assert result.returncode == 0, result.stderr
    assert "starts node" in result.stderr.lower() or "starts node.exe" in result.stderr.lower()
    config = load_config(root / "gazua.yaml").config
    assert config.mcp is not None
    assert config.mcp.args == [project.config["mcp"]["args"][0], str(project.state)]
    # The second page holds send_email: discovery followed the cursor.
    assert sorted(config.tools) == ["get_order", "search_docs", "send_email"]
    assert all(tool.requires_dry_run for tool in config.tools.values())
    assert config.tools["send_email"].sensitive is True
    # readOnlyHint is the server's claim and grants nothing.
    assert "readOnlyHint" not in (root / "gazua.yaml").read_text(encoding="utf-8")
    assert project.calls() == []
    assert "none was called" in result.stdout


def test_init_refuses_a_server_that_does_not_start(tmp_path: Path) -> None:
    require_typescript()
    project = McpProject(tmp_path / "holder")
    root = tmp_path / "empty"
    root.mkdir()

    result = project.cli(
        "init", str(root), "--mcp", "gazua-missing-server", "--mcp-arg", "token-GAZUA-SECRET"
    )

    assert result.returncode == 2
    assert "gazua-missing-server" in result.stderr
    assert "mcp_start_failed" in result.stderr
    assert "token-GAZUA-SECRET" not in result.stderr + result.stdout
    assert not (root / "gazua.yaml").exists()


def test_mcp_options_need_mcp(tmp_path: Path) -> None:
    project = McpProject(tmp_path / "holder")

    result = project.cli("init", str(tmp_path), "--mcp-arg", "server.js")

    assert result.returncode == 2
    assert "--mcp" in result.stderr


@pytest.mark.parametrize("pages", [1, 3])
def test_python_server_pages_are_all_read(tmp_path: Path, pages: int) -> None:
    from gazua.config.models import GazuaConfig
    from gazua.runtime.engine import describe_tools

    project = McpProject(tmp_path / "project")
    tools = [{"name": f"tool_{index}", "inputSchema": {"type": "object"}} for index in range(6)]
    project.set_tools(tools, page_size=6 // pages)
    config = GazuaConfig.model_validate(json.loads((project.root / "gazua.yaml").read_text()))

    document = describe_tools(config, project_root=project.root, timeout=30)

    assert [tool["name"] for tool in document["mcp"]["tools"]] == [f"tool_{i}" for i in range(6)]
    assert project.calls() == []
