from pathlib import Path

from mcp_support import ATTACKER, McpProject


def test_typescript_idor_vulnerable_and_hardened(tmp_path: Path) -> None:
    project = McpProject(tmp_path / "project", server="typescript")

    vulnerable = project.run_tools("idor-01")

    [found] = vulnerable.verdicts.results
    assert found.state == "finding"
    assert vulnerable.exit_code == 1
    [proof] = found.proof
    assert proof.signal == "victim_record_access"
    assert proof.facts["tool"] == "get_order"
    [call] = project.calls()
    assert call["tool"] == "get_order"
    assert call["arguments"]["order_id"] == "order-victim"
    # The attacker identity is imposed over whatever a caller could send.
    assert call["arguments"]["actor_id"] == ATTACKER

    project.harden()
    project.clear_calls()
    hardened = project.run_tools("idor-01")

    [quiet] = hardened.verdicts.results
    assert quiet.state == "resisted"
    assert quiet.coverage == "complete"
    assert hardened.exit_code == 0
    assert quiet.attack_key == found.attack_key
    assert [item["arguments"]["actor_id"] for item in project.calls()] == [ATTACKER]


def test_tools_mode_needs_no_entrypoint_and_no_python_target(tmp_path: Path) -> None:
    project = McpProject(tmp_path / "project", server="typescript")
    assert "entrypoint" not in project.config

    result = project.cli("run", "--tools", "--mold", "idor-01")

    assert result.returncode == 1, result.stderr
    assert "idor-01" in result.stdout
    assert "Records of another user" in result.stdout


def test_unsupported_schema_is_not_tested(tmp_path: Path) -> None:
    project = McpProject(tmp_path / "project")
    project.set_tools(
        [
            {
                "name": "get_order",
                "inputSchema": {"type": "object", "$ref": "https://example.test/schema.json"},
            }
        ]
    )

    result = project.run_tools("idor-01")

    [item] = result.verdicts.results
    assert item.state == "not_tested"
    assert project.calls() == []
    assert "mcp_schema_unsupported" in result.inventory.get("get_order").diagnostics
