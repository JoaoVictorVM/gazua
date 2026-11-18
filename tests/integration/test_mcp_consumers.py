from pathlib import Path
from typing import Any

from mcp_support import ATTACKER, McpProject


def test_wrapper_tools_agent_contracts_over_mcp(tmp_path: Path) -> None:
    project = McpProject(tmp_path / "project", server="typescript")
    calls: list[dict[str, Any]] = []
    returns: list[Any] = []

    def keep(record: Any, evidence: Any) -> None:
        calls.extend(item.model_dump(mode="json") for item in evidence.calls)
        if evidence.returns is not None:
            returns.extend(evidence.returns.value(item.seq) for item in evidence.calls)

    tools = project.run_tools("idor-01", on_evidence=keep)

    # F07: native verdict, gate, exit code and reproduction command, as for Python targets.
    [found] = tools.verdicts.results
    assert found.state == "finding"
    assert tools.exit_code == 1
    assert tools.has_gated_findings
    assert tools.reproduction[found.attack_key][:3] == ["gazua", "run", "--tools"]
    # F04: the native call log and the private return channel hold the MCP call.
    [call] = calls
    assert call["tool"] == "get_order"
    assert call["actor"] == {"id": ATTACKER, "source": "actor_arg"}
    assert call["dry_run"] is False
    assert call["outcome"] == "returned"
    [captured] = returns
    assert captured is not None
    assert captured.original["owner_id"] == "victim"

    # F04 + F09: an injection in a text result reaches the agent through the proxy, and the
    # effect that follows it is attributed with the existing rules.
    project.use_agent("follow")
    project.update(
        agent_entries={"tool_result": {"tool": "search_docs", "request": "Check my order status."}},
        legit_tasks=[{"request": "Where is my order?", "expected_tool": "get_order"}],
    )
    agent = project.run_agent("idor-06", repetitions=2)

    [attack] = agent.verdicts.results
    assert attack.state == "finding"
    assert attack.rate == 1.0
    assert agent.legitimate_use is not None
    assert agent.legitimate_use.succeeded == 1
    assert agent.exit_code == 1
