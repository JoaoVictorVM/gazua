from collections import Counter
from typing import Any

import pytest
from agent_factory import CANARY, agent_entries, agent_molds, config, inventory, mold

from gazua.catalog.loader import load_catalog
from gazua.catalog.models import DAMAGES
from gazua.diagnostics import ConfigError
from gazua.modes.agent_models import AgentOptions
from gazua.modes.agent_plan import (
    EXECUTOR,
    attack_key,
    plan_agent,
    quick_selection,
)
from gazua.modes.agent_plan import (
    agent_molds as select_agent_molds,
)


def plan_of(molds: Any = None, configuration: Any = None, repetitions: int = 5) -> Any:
    chosen = configuration if configuration is not None else config()
    return plan_agent(
        list(molds if molds is not None else agent_molds()),
        chosen,
        inventory(chosen),
        repetitions=repetitions,
    )


def test_agent_defaults_expand_five_round_robin_slots() -> None:
    assert AgentOptions().effective_repetitions == 5
    assert AgentOptions(quick=True).effective_repetitions == 1
    molds = select_agent_molds(agent_entries())
    tools_only = {item.id for item in load_catalog().molds if "agent" not in item.supported_modes}
    assert len(molds) == 15
    assert not tools_only & {item.id for item in molds}

    plan = plan_of(molds)
    executable = [item for item in plan.scenarios if item.requests]
    assert executable
    assert all(len(item.requests) == 5 for item in executable)
    assert all(len(item.context.requests) == 5 for item in plan.scenarios)
    requests = plan.requests
    assert [request.key for request in requests[:1]] == ["legitimate:0"]
    attacks = plan.attack_requests
    # The first repetition of every scenario comes before any second repetition.
    first_round = attacks[: len(executable)]
    assert {request.repetition for request in first_round} == {1}
    assert [request.repetition for request in attacks] == sorted(
        request.repetition for request in attacks
    )
    assert len(attacks) == 5 * len(executable)
    assert len({request.key for request in requests}) == len(requests)
    assert {request.executor for request in requests} == {EXECUTOR}
    assert all(request.mode == "agent" for request in requests)
    assert plan.impeded_slots == 5 * (len(plan.scenarios) - len(executable))
    # Planning twice gives the same order and keys.
    assert [request.key for request in plan_of(molds).requests] == [r.key for r in requests]


def test_quick_selects_up_to_fifteen_without_hiding_unavailable_entries() -> None:
    molds = list(agent_molds())
    selection = quick_selection(molds)
    assert len(selection) == 15
    assert [item.id for item in quick_selection(list(reversed(molds)))] == [
        item.id for item in selection
    ]
    # The first round takes one mold of each damage, in catalog damage order.
    assert [item.damage for item in selection[: len(DAMAGES)]] == list(DAMAGES)
    assert len(quick_selection(molds, limit=4)) == 4
    assert {item.damage for item in quick_selection(molds, limit=6)} == set(DAMAGES)

    # Without agent entries, indirect molds stay selected and are reported as not tested.
    bare = config(agent_entries={}, legit_tasks=[])
    plan = plan_of(selection, bare, repetitions=1)
    assert len(plan.selection.molds) == 15
    blocked = {
        item.mold_id: item.impediments for item in plan.selection.molds if not item.executable
    }
    assert blocked["memory-01"] == ["entry_unavailable"]
    assert blocked["secret-05"] == ["entry_unavailable"]
    assert all(len(item.requests) <= 1 for item in plan.scenarios)
    assert plan.legitimate == ()


def test_quick_and_exact_mold_preserve_single_selection() -> None:
    [only] = select_agent_molds(agent_entries(), "secret-04")
    assert only.id == "secret-04"
    plan = plan_of([only], repetitions=1)
    assert [item.mold_id for item in plan.selection.molds] == ["secret-04"]
    assert all(len(item.requests) == 1 for item in plan.scenarios)

    for unknown in ("secret-01", "secret-404", "SECRET-04"):
        with pytest.raises(ConfigError) as error:
            select_agent_molds(agent_entries(), unknown)
        assert error.value.diagnostics[0].code == "mold_not_found"


def test_binding_dimensions_and_entry_tool_are_independent() -> None:
    chosen = config(
        tools={
            **config().model_dump(mode="json", exclude_unset=True)["tools"],
            "cancel_order": {"sensitive": True},
        }
    )
    plan = plan_of(None, chosen)
    counts = Counter(item.context.mold.id for item in plan.scenarios)
    # One scenario per sensitive tool, one per victim record; no product with canaries.
    assert counts["spending-03"] == 2
    assert counts["spending-04"] == 2
    assert counts["idor-05"] == 1
    assert counts["secret-04"] == 1
    assert counts["output-03"] == 1

    by_mold = {item.context.mold.id: item for item in plan.scenarios}
    idor = by_mold["idor-05"]
    assert idor.context.tool_name == "get_order"
    assert idor.context.record_index == 0
    assert {request.actor for request in idor.requests} == {"attacker"}
    secret = by_mold["secret-04"]
    assert secret.context.canary_index is None
    assert {request.actor for request in secret.requests} == {None}

    # The effect is judged on refund, while the text arrives through the declared carrier.
    indirect = [item for item in plan.scenarios if item.context.mold.id == "spending-04"]
    assert {item.context.tool_name for item in indirect} == {"refund", "cancel_order"}
    for item in indirect:
        for request in item.requests:
            assert [injection.tool for injection in request.injections] == ["search_docs"]
            assert [injection.max_deliveries for injection in request.injections] == [1]
            assert request.injections[0].id == f"{request.key}#turn1"
    assert not by_mold["spending-03"].requests[0].injections

    keys = [item.context.attack_key for item in plan.scenarios]
    assert len(set(keys)) == len(keys)
    assert all(CANARY not in key for key in keys)
    assert attack_key(mold("secret-05"), None, None, None, "search_docs") != attack_key(
        mold("secret-05"), None, None, None, "read_memory"
    )

    # A mold without its declarations is planned and impeded, never dropped.
    bare = config(fixtures={}, canaries=[], output_sink=None)
    impeded = {
        item.context.mold.id: item.context
        for item in plan_of(None, bare).scenarios
        if not item.requests
    }
    assert "idor-05" in impeded
    assert "secret-04" in impeded
