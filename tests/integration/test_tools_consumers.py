"""Contracts that later consumers of tools mode rely on, checked with minimal stand-ins.

These stand-ins do not implement the demo, CI, benchmark or MCP features; they only show that
the result they will receive is the native one and that no consumer path skips the safety rules.
"""

from typing import Any

from gazua.config.loader import load_config
from gazua.modes.tools import discover_tools
from gazua.modes.tools_models import ParameterInfo, ToolsResult
from gazua.verdicts.models import AttackResult, VerdictSummary


def demo_consumer(result: ToolsResult) -> list[tuple[str, str]]:
    return [(item.mold_id, item.state) for item in result.verdicts.results]


def ci_consumer(result: ToolsResult) -> tuple[bool, int]:
    return result.has_gated_findings, result.exit_code


def test_demo_consumer_receives_native_results(tools_project: Any) -> None:
    result = tools_project.run("idor-01")

    assert isinstance(result.verdicts, VerdictSummary)
    assert all(isinstance(item, AttackResult) for item in result.verdicts.results)
    assert VerdictSummary.model_validate_json(result.verdicts.model_dump_json()) == result.verdicts
    assert ToolsResult.model_validate_json(result.model_dump_json()) == result
    assert demo_consumer(result) == [("idor-01", "finding")]


def test_ci_consumer_receives_same_gate_and_error_status(tools_project: Any) -> None:
    gated = tools_project.run("idor-01")
    assert ci_consumer(gated) == (True, 1)

    (tools_project.root / "slow").write_text("x", encoding="utf-8")
    failed = tools_project.run(molds=("idor-01", "permission-03"), overrides={"timeout": 3})
    assert failed.has_gated_findings
    assert ci_consumer(failed) == (True, 2)


def test_benchmark_consumer_asserts_effects_and_not_applicability(tools_project: Any) -> None:
    vulnerable = tools_project.run("secret-01")
    tools_project.harden()
    hardened = tools_project.run("secret-01")

    assert {item.state for item in vulnerable.verdicts.results} == {"finding"}
    assert {item.state for item in hardened.verdicts.results} == {"resisted"}

    (tools_project.root / "empty_target.py").write_text(
        "def entrypoint(message):\n    raise AssertionError('never called')\n", encoding="utf-8"
    )
    tools_project.write(entrypoint="empty_target:entrypoint", tools={}, fixtures={})
    empty = tools_project.run("permission-01")
    [item] = empty.verdicts.results
    assert item.state == "not_applicable"
    assert [reason.code for reason in item.reasons] == ["no_applicable_tool"]
    assert empty.exit_code == 2


def test_transport_boundary_does_not_bypass_safety(tools_project: Any) -> None:
    config = load_config(tools_project.root / "gazua.yaml").config
    honest = discover_tools(config, tools_project.root, timeout=30)
    unsafe = honest.get("send_email")
    assert unsafe is not None
    assert unsafe.skip_reason == "missing_safe"
    forged = honest.model_copy(
        update={
            "tools": [
                tool.model_copy(update={"safe": True}) if tool.name == "send_email" else tool
                for tool in honest.tools
            ]
        }
    )

    result = tools_project.run("permission-03", inventory=forged)

    assert "send_email" not in {item["kind"] for item in tools_project.effects()}
    contexts = {context.attack_key: context for context in result.contexts}
    [skipped] = [
        item
        for item in result.verdicts.results
        if contexts[item.attack_key].tool_name == "send_email"
    ]
    assert skipped.state == "not_tested"
    assert "tool.safe" in skipped.reasons[0].missing

    document = tools_project.document()
    document["tools"]["phantom"] = {"safe": True, "sensitive": True, "actor_arg": "actor"}
    tools_project.write(tools=document["tools"])
    config = load_config(tools_project.root / "gazua.yaml").config
    honest = discover_tools(config, tools_project.root, timeout=30)
    phantom = honest.get("phantom")
    assert phantom is not None
    assert phantom.skip_reason == "tool_not_found"
    claimed = honest.model_copy(
        update={
            "tools": [
                tool.model_copy(
                    update={
                        "registered": True,
                        "signature_available": True,
                        "parameters": [
                            ParameterInfo(
                                name="actor", kind="positional_or_keyword", has_default=True
                            )
                        ],
                    }
                )
                if tool.name == "phantom"
                else tool
                for tool in honest.tools
            ]
        }
    )

    refused = tools_project.run("permission-03", inventory=claimed)

    by_tool = {
        contexts.tool_name: record.status
        for contexts in refused.contexts
        for record in refused.engine.records
        if record.request_key == contexts.requests[0].request_key
    }
    assert by_tool["phantom"] == "crashed"
    assert refused.exit_code == 2
