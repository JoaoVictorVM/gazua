import inspect
from collections.abc import Callable
from pathlib import Path
from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from gazua.config.models import GazuaConfig
from gazua.mcp.discovery import EXTRA_PARAMETER, forwarder_signature, reconcile
from gazua.mcp.models import inventory_from, tool_from_definition
from gazua.mcp.policy import forwarding_allowed

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"order_id": {"type": "string"}, "actor_id": {"type": "string"}},
    "required": ["order_id"],
    "additionalProperties": False,
}
annotations = st.dictionaries(
    st.sampled_from(["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"]),
    st.booleans(),
)
declarations = st.one_of(
    st.none(),
    st.fixed_dictionaries(
        {},
        optional={
            "safe": st.booleans(),
            "sensitive": st.booleans(),
            "forbidden": st.booleans(),
        },
    ),
)


@given(hints=annotations, declaration=declarations)
def test_annotations_cannot_grant_safety(
    hints: dict[str, bool], declaration: dict[str, Any] | None
) -> None:
    listed = tool_from_definition({"name": "op", "inputSchema": SCHEMA, "annotations": hints})
    inventory = inventory_from("2025-06-18", [listed])
    tools = {} if declaration is None else {"op": declaration}
    config = GazuaConfig.model_validate(
        {
            "schema_version": 1,
            "mcp": {"transport": "stdio", "command": "server"},
            "tools": tools,
        }
    )

    allowed = forwarding_allowed(config, "op", inventory.digests())
    discovered = reconcile(config, inventory).get("op")

    expected = declaration is not None and not config.tools["op"].requires_dry_run
    assert allowed is expected
    assert discovered is not None
    assert discovered.safe is (declaration is not None and declaration.get("safe") is True)


def test_new_tool_is_never_released_by_its_declaration() -> None:
    config = GazuaConfig.model_validate(
        {
            "schema_version": 1,
            "mcp": {"transport": "stdio", "command": "server"},
            "tools": {"late": {"safe": True, "sensitive": False}},
        }
    )

    assert forwarding_allowed(config, "late", None)
    assert not forwarding_allowed(config, "late", {"other": "0" * 64})


def test_signature_keeps_schema_names_and_marks_optional_ones() -> None:
    listed = tool_from_definition({"name": "get_order", "inputSchema": SCHEMA})

    signature = forwarder_signature(listed)

    assert list(signature.parameters) == ["actor_id", "order_id"]
    assert signature.parameters["order_id"].default is inspect.Parameter.empty
    assert signature.parameters["actor_id"].default is not inspect.Parameter.empty
    open_ended = forwarder_signature(
        tool_from_definition(
            {"name": "x", "inputSchema": {"type": "object", "properties": {"a-b": {}}}}
        )
    )
    assert list(open_ended.parameters) == [EXTRA_PARAMETER]


def test_actor_overrides_model_arguments(
    start_session: Callable[..., Path], read_log: Callable[[Path], list[dict[str, Any]]]
) -> None:
    from conftest import tool_policy
    from gazua.integration.proxy import make_proxy

    listed = tool_from_definition({"name": "get_order", "inputSchema": SCHEMA})
    received: list[dict[str, Any]] = []

    def forward(**values: Any) -> str:
        received.append(values)
        return "ok"

    forward.__signature__ = forwarder_signature(listed)  # type: ignore[attr-defined]
    proxy = make_proxy("get_order", forward)
    log = start_session(
        actor={"id": "attacker", "role": "attacker"},
        tools={"get_order": tool_policy(dry_run=False, actor_arg="actor_id")},
    )

    proxy(order_id="order-victim", actor_id="victim")

    assert received == [{"order_id": "order-victim", "actor_id": "attacker"}]
    [record] = read_log(log)
    assert record["actor"] == {"id": "attacker", "source": "actor_arg"}


def test_local_as_user_does_not_satisfy_mcp_identity() -> None:
    from tools_factory import mold

    from gazua.catalog.selection import inspect_requirements

    config = GazuaConfig.model_validate(
        {
            "schema_version": 1,
            "mcp": {"transport": "stdio", "command": "server"},
            "target": {"as_user": "hooks:as_user"},
            "tools": {"get_order": {"safe": True, "sensitive": False}},
            "fixtures": {
                "attacker": {"id": "a"},
                "victim": {
                    "id": "v",
                    "records": [{"tool": "get_order", "id_arg": "order_id", "id": "o"}],
                },
            },
        }
    )

    report = inspect_requirements(mold("idor-01"), config, "get_order")

    assert "identity" in report.missing
