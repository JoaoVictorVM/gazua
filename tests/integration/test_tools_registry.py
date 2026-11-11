from typing import Any

from gazua.config.loader import load_config
from gazua.modes.tools import NO_TOOL_CAN_RUN, discover_tools
from gazua.modes.tools_presentation import LATE_REGISTRATION

LATE_TARGET = """
import gazua


def get_order(order_id, user_id=None, actor=None):
    return None


def entrypoint(message):
    tools = gazua.wrap({"get_order": get_order})
    return str(tools)
"""


def test_wrap_and_decorator_import_without_agent_execution(tools_project: Any) -> None:
    config = load_config(tools_project.root / "gazua.yaml").config

    inventory = discover_tools(config, tools_project.root, timeout=30)

    assert inventory.complete
    described = {tool.name: tool for tool in inventory.tools}
    assert described["send_email"].registered
    assert described["send_email"].supports_sync
    assert described["archive_order"].supports_async
    assert described["get_order"].required_arguments == ["order_id"]
    assert [tool.name for tool in inventory.runnable] == [
        "archive_order",
        "cancel_order",
        "get_order",
        "refund",
    ]
    assert tools_project.effects() == []

    (tools_project.root / "late_target.py").write_text(LATE_TARGET, encoding="utf-8")
    tools_project.write(
        entrypoint="late_target:entrypoint",
        tools={"get_order": {"safe": True, "sensitive": False}},
    )
    late = tools_project.cli("--tools")
    assert late.returncode == 2
    assert NO_TOOL_CAN_RUN in late.stdout
    assert LATE_REGISTRATION in late.stdout
    assert "get_order: not tested, not registered when the test module was imported" in late.stdout


def test_attacker_arg_and_context_hook_are_imposed(tools_project: Any) -> None:
    document = tools_project.document()
    document["tools"]["get_order"].pop("actor_arg")
    tools_project.write(tools=document["tools"], target={"as_user": "tools_target:as_user"})

    hooked = tools_project.run("idor-01")
    argument = tools_project.run("permission-03")

    [found] = hooked.verdicts.results
    assert found.state == "finding"
    effects = tools_project.effects()
    assert {"kind": "as_user", "identity": "attacker-1"} in effects
    refunds = [item for item in effects if item["kind"] == "refund"]
    assert refunds
    assert {item["actor"] for item in refunds} == {"attacker-1"}
    assert argument.exit_code == 1

    tools_project.clear_effects()
    document["tools"]["archive_order"] = {"safe": True, "sensitive": True}
    tools_project.write(tools=document["tools"], target={"as_user": "tools_target:as_user_async"})
    asynchronous = tools_project.run("permission-03")
    archived = [
        item
        for item in asynchronous.verdicts.results
        if any(
            context.attack_key == item.attack_key and context.tool_name == "archive_order"
            for context in asynchronous.contexts
        )
    ]
    assert [item.state for item in archived] == ["finding"]
    assert {"kind": "as_user_async", "identity": "attacker-1"} in tools_project.effects()
