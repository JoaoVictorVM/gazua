from collections import Counter
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st
from tools_factory import (
    CANARY,
    SECOND_CANARY,
    config,
    config_document,
    inventory,
    mold,
    tools_molds,
)

from gazua.catalog.bindings import BindingContext
from gazua.catalog.loader import load_catalog
from gazua.modes.tools_plan import EXECUTOR, attack_key, plan_tools


def plan_of(configuration: Any = None, **options: Any) -> Any:
    chosen = configuration if configuration is not None else config()
    return plan_tools(tools_molds(), chosen, inventory(chosen), **options)


def by_mold(plan: Any) -> dict[str, list[Any]]:
    grouped: dict[str, list[Any]] = {}
    for attack in plan.attacks:
        grouped.setdefault(attack.context.mold.id, []).append(attack)
    return grouped


def test_expands_all_compatible_bindings() -> None:
    plan = plan_of()

    counts = Counter(attack.context.mold.id for attack in plan.attacks)
    assert counts == {
        "idor-01": 3,
        "idor-02": 3,
        "idor-03": 3,
        "idor-04": 3,
        "secret-01": 6,
        "secret-02": 6,
        "secret-03": 6,
        "output-01": 5,
        "output-02": 5,
        "permission-01": 1,
        "permission-02": 1,
        "permission-03": 2,
        "permission-04": 2,
        "spending-01": 2,
        "spending-02": 2,
    }
    agent_only = {item.id for item in load_catalog().molds if "tools" not in item.supported_modes}
    assert not agent_only & set(counts)
    keys = [attack.context.attack_key for attack in plan.attacks]
    assert len(set(keys)) == len(keys)
    requests = plan.requests
    assert len({request.key for request in requests}) == len(requests)
    assert {request.executor for request in requests} == {EXECUTOR}
    assert {request.repetition for request in requests} == {1}
    sinks = by_mold(plan)["output-01"]
    assert [attack.context.tool_name for attack in sinks] == [
        "delete_account",
        "get_invoice",
        "get_order",
        "refund",
        "send_email",
    ]
    assert {attack.context.marker_id for attack in sinks} == {"markup_marker"}


def test_record_index_is_local_to_tool() -> None:
    configuration = config()
    units = by_mold(plan_of(configuration))["idor-01"]

    assert [(item.context.tool_name, item.context.record_index) for item in units] == [
        ("get_invoice", 0),
        ("get_order", 0),
        ("get_order", 1),
    ]
    for item in units:
        assert item.request is not None
        assert item.request.payload["record_index"] == item.context.record_index
        bound = BindingContext.from_config(
            configuration, item.context.tool_name, record_index=item.context.record_index
        )
        assert bound.record is not None
        assert bound.record.tool == item.context.tool_name
    order_ids = [
        BindingContext.from_config(configuration, "get_order", record_index=index).record
        for index in (0, 1)
    ]
    assert [record.id for record in order_ids if record] == ["order-victim-1", "order-victim-2"]


def test_canaries_expand_only_when_used() -> None:
    grouped = by_mold(plan_of())

    assert [item.context.canary_index for item in grouped["secret-01"]] == [0, 1] * 3
    for mold_id in ("idor-01", "permission-01", "output-01", "spending-02"):
        assert {item.context.canary_index for item in grouped[mold_id]} == {None}
    for mold_id in ("permission-01", "output-01", "spending-02"):
        assert {item.context.record_index for item in grouped[mold_id]} == {None}
    secret_keys = [item.context.attack_key for item in grouped["secret-01"]]
    assert all(CANARY not in key and SECOND_CANARY not in key for key in secret_keys)

    no_canaries = by_mold(plan_of(config(canaries=[])))["secret-01"]
    assert len(no_canaries) == 3
    assert {item.context.impediment.reason for item in no_canaries if item.context.impediment} == {
        "missing_declarations"
    }
    assert all(item.request is None for item in no_canaries)


def test_unsafe_candidates_remain_not_tested() -> None:
    grouped = by_mold(plan_of())
    unsafe = [item for item in grouped["permission-03"] if item.context.tool_name == "send_email"]

    [item] = unsafe
    assert item.request is None
    assert item.context.impediment is not None
    assert item.context.impediment.reason == "missing_declarations"
    assert item.context.impediment.missing == ["tool.safe"]
    released = [item for item in grouped["permission-03"] if item.context.tool_name == "refund"]
    assert released[0].request is not None
    assert all(
        request.payload["tool_name"] != "send_email"
        for request in plan_of().requests
        if request.mold_id != "output-01" and request.mold_id != "output-02"
    )


def test_missing_fixture_has_own_context() -> None:
    document = config_document()
    document["fixtures"] = {"attacker": {"id": "attacker-1"}}
    plan = plan_of(config(**{"fixtures": document["fixtures"]}))
    grouped = by_mold(plan)

    for mold_id in ("idor-01", "secret-01"):
        [item] = grouped[mold_id]
        assert item.request is None
        assert item.context.tool_name is None
        assert item.context.impediment is not None
        assert item.context.impediment.reason == "missing_declarations"
        assert "fixtures.victim.records" in item.context.impediment.missing
    assert grouped["permission-01"][0].request is not None
    assert grouped["spending-02"][0].request is not None


def test_complete_inventory_without_candidate_is_not_applicable() -> None:
    document = config_document()
    del document["tools"]["delete_account"]
    configuration = config(tools=document["tools"])
    complete = plan_tools([mold("permission-01")], configuration, inventory(configuration))
    partial = plan_tools(
        [mold("permission-01")], configuration, inventory(configuration, complete=False)
    )

    [known] = complete.attacks
    [unknown] = partial.attacks
    assert known.context.impediment is not None
    assert known.context.impediment.reason == "no_applicable_tool"
    assert unknown.context.impediment is not None
    assert unknown.context.impediment.reason == "tool_not_found"
    assert known.context.attack_key == unknown.context.attack_key


def test_registration_problems_are_impediments() -> None:
    configuration = config()
    functions = inventory_functions()
    del functions["refund"]
    described = inventory(configuration, functions, ambiguous=("delete_account",))
    plan = plan_tools([mold("permission-01"), mold("permission-03")], configuration, described)

    reasons = {
        (item.context.mold.id, item.context.tool_name): item.context.impediment.reason
        for item in plan.attacks
        if item.context.impediment is not None
    }
    assert reasons[("permission-01", "delete_account")] == "tool_name_conflict"
    assert reasons[("permission-03", "refund")] == "tool_not_found"
    assert plan.requests == []


def inventory_functions() -> dict[str, Any]:
    from tools_factory import FUNCTIONS

    return dict(FUNCTIONS)


def test_attack_keys_are_stable_and_unique() -> None:
    first = [item.context.attack_key for item in plan_of().attacks]
    second = [item.context.attack_key for item in plan_of().attacks]

    assert first == second
    assert all(len(key) <= 200 and key.isascii() for key in first)
    assert all(
        key.startswith(f"tools:{item.context.mold.id}:")
        for key, item in zip(first, plan_of().attacks, strict=True)
    )


@settings(max_examples=25, deadline=None)
@given(order=st.permutations(list(range(len(tools_molds())))))
def test_mold_order_does_not_change_units(order: list[int]) -> None:
    configuration = config()
    shuffled = [tools_molds()[index] for index in order]
    expected = {item.context.attack_key: item.request for item in plan_of(configuration).attacks}

    plan = plan_tools(shuffled, configuration, inventory(configuration))

    assert {item.context.attack_key: item.request for item in plan.attacks} == expected


def test_key_preserves_record_id_type() -> None:
    chosen = mold("idor-01")
    from gazua.config.models import FixtureRecord

    as_text = FixtureRecord(tool="get_invoice", id_arg="invoice_id", id="7")
    as_int = FixtureRecord(tool="get_invoice", id_arg="invoice_id", id=7)

    assert attack_key(chosen, "get_invoice", (0, as_text), None) != attack_key(
        chosen, "get_invoice", (0, as_int), None
    )
    assert attack_key(chosen, "get_invoice", (0, as_int), None) != attack_key(
        chosen, "get_invoice", (1, as_int), None
    )
    string_ids = by_mold(plan_of())["idor-04"]
    reasons = {item.context.tool_name: item.context.impediment for item in string_ids}
    assert reasons["get_invoice"] is None
    assert {
        item.context.impediment.reason
        for item in string_ids
        if item.context.tool_name == "get_order" and item.context.impediment
    } == {"not_applicable"}


@settings(max_examples=10, deadline=None)
@given(language=st.sampled_from(["en", "pt"]))
def test_translations_do_not_change_units(language: str) -> None:
    english = plan_of(language="en")
    translated = plan_of(language=language)

    assert [item.context for item in translated.attacks] == [
        item.context for item in english.attacks
    ]
    for left, right in zip(english.requests, translated.requests, strict=True):
        assert left.key == right.key
        assert {**left.payload, "language": None} == {**right.payload, "language": None}
        assert left.actor == right.actor
