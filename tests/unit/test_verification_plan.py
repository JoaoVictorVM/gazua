from typing import Any

import pytest
from baseline_factory import baseline, entry, reference
from tools_factory import config, inventory
from tools_factory import mold as tools_mold

from gazua.baseline.models import original_key, scenario_digest
from gazua.baseline.plan import build_plan, check_budget
from gazua.baseline.selection import Selection, VerifyError
from gazua.modes.tools_plan import plan_tools
from gazua.reports.builder import finding_id
from gazua.runtime.engine import effective_limits
from gazua.runtime.run_models import LimitOverrides

TARGET = "tools_target:entrypoint"


def selection(*languages: str, mold_id: str = "idor-01", tool: str = "get_order") -> Selection:
    configuration = config()
    contexts = [
        item
        for item in plan_tools(
            [tools_mold(mold_id)], configuration, inventory(configuration)
        ).contexts
        if item.tool_name == tool
    ]
    scenarios = sorted(
        (
            reference(scenario_digest(item.attack_key), language)
            for item in contexts
            for language in (languages or ("en",))
        ),
        key=lambda item: (item["scenario_digest"], item["language"]),
    )
    accepted = baseline(entry(finding_id(TARGET, "tools", mold_id, tool), scenarios=scenarios))
    return Selection(accepted.entries[0], "tools", tools_mold(mold_id))


def test_twenty_slots_per_scenario_and_language() -> None:
    configuration = config()
    plan = build_plan(selection("en", "pt"), configuration, inventory(configuration))

    assert plan.languages == ("en", "pt")
    pairs = [(item.reference.scenario_digest, item.reference.language) for item in plan.samples]
    assert len(pairs) == len(set(pairs))
    assert {language for _, language in pairs} == {"en", "pt"}
    for sample in plan.samples:
        assert len(sample.context.requests) == 20
        assert [slot.repetition for slot in sample.context.requests] == list(range(1, 21))
        split = original_key(sample.context.attack_key)
        assert split is not None
        assert scenario_digest(split[0]) == sample.reference.scenario_digest
        assert split[1] == sample.reference.language
        assert len(sample.context.attack_key) <= 200
        for request in sample.requests:
            assert request.payload["attack_key"] == sample.context.attack_key
            assert request.payload["language"] == sample.reference.language
    keys = [request.key for request in plan.requests]
    assert len(keys) == len(set(keys)) == 20 * len(plan.samples)
    assert [request.repetition for request in plan.requests[: len(plan.samples)]] == [1] * len(
        plan.samples
    )


def test_retries_are_not_extra_repetitions() -> None:
    configuration = config()
    plan = build_plan(selection(), configuration, inventory(configuration))

    for sample in plan.samples:
        slots = {slot.request_key: slot.repetition for slot in sample.context.requests}
        assert {request.key: request.repetition for request in sample.requests} == slots
    # The regular plan keeps a single repetition per tools unit.
    regular = plan_tools([tools_mold("idor-01")], configuration, inventory(configuration))
    assert all(len(item.requests) == 1 for item in regular.contexts)
    assert all(request.key.endswith(":r1") for request in regular.requests)


def test_only_selected_finding_is_executed() -> None:
    configuration = config()
    plan = build_plan(selection(tool="get_order"), configuration, inventory(configuration))

    assert {item.context.tool_name for item in plan.samples} == {"get_order"}
    assert {item.context.mold.id for item in plan.samples} == {"idor-01"}
    assert all(request.mold_id == "idor-01" for request in plan.requests)
    assert all(request.payload["tool_name"] == "get_order" for request in plan.requests)


def test_one_budget_for_all_languages() -> None:
    configuration = config()
    plan = build_plan(selection("en", "pt"), configuration, inventory(configuration))
    slots = len(plan.requests)

    check_budget(plan, effective_limits(configuration, LimitOverrides(max_runs=slots)))
    with pytest.raises(VerifyError) as caught:
        check_budget(plan, effective_limits(configuration, LimitOverrides(max_runs=slots - 1)))
    assert caught.value.code == "verification_insufficient_budget"
    costly: Any = config(limits={"max_cost": 1, "cost_per_run": 0.5})
    with pytest.raises(VerifyError):
        check_budget(plan, effective_limits(costly, LimitOverrides(max_runs=slots)))
