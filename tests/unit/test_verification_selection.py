from typing import Any

import pytest
from baseline_factory import baseline, entry, reference
from tools_factory import config, inventory
from tools_factory import mold as tools_mold

from gazua.baseline.models import scenario_digest
from gazua.baseline.plan import build_plan
from gazua.baseline.selection import VerifyError, resolve
from gazua.catalog.loader import load_catalog
from gazua.modes.tools_plan import plan_tools
from gazua.reports.builder import finding_id

TARGET = "tools_target:entrypoint"


def entries() -> Any:
    return load_catalog(release="v0.2").entries


def accepted(tool: str, mold_id: str = "idor-01", **fields: Any) -> dict[str, Any]:
    configuration = config()
    contexts = [
        item
        for item in plan_tools(
            [tools_mold(mold_id)], configuration, inventory(configuration)
        ).contexts
        if item.tool_name == tool
    ]
    scenarios = sorted(
        (reference(scenario_digest(item.attack_key)) for item in contexts),
        key=lambda item: item["scenario_digest"],
    )
    return entry(finding_id(TARGET, "tools", mold_id, tool), scenarios=scenarios, **fields)


def test_exact_id_and_unique_alias_resolve_same_finding() -> None:
    known = baseline(accepted("get_order"))
    identifier = known.entries[0].id

    by_id = resolve(identifier, known, config(), entries())
    by_alias = resolve("idor-01", known, config(), entries(), "tools")

    assert by_id.entry == by_alias.entry
    assert (by_id.mode, by_id.mold.id) == ("tools", "idor-01")
    with pytest.raises(VerifyError) as unknown:
        resolve("idor-02", known, config(), entries())
    assert unknown.value.code == "verification_finding_unknown"
    with pytest.raises(VerifyError) as other_mode:
        resolve(identifier, known, config(), entries(), "agent")
    assert other_mode.value.code == "verification_finding_unknown"
    elsewhere = baseline(entry(finding_id("other:entrypoint", "tools", "idor-01", "get_order")))
    with pytest.raises(VerifyError):
        resolve(elsewhere.entries[0].id, elsewhere, config(), entries())


def test_ambiguous_alias_requires_full_id() -> None:
    known = baseline(accepted("get_order"), accepted("get_invoice"))

    with pytest.raises(VerifyError) as caught:
        resolve("idor-01", known, config(), entries(), "tools")

    assert caught.value.code == "verification_finding_ambiguous"
    assert sorted(caught.value.choices) == sorted(item.id for item in known.entries)
    chosen = resolve(known.entries[0].id, known, config(), entries())
    assert chosen.entry.id == known.entries[0].id


def test_removed_historic_scenario_blocks_closure() -> None:
    historic = accepted("get_order")
    historic["scenarios"] = sorted(
        [*historic["scenarios"], reference("f" * 64)], key=lambda item: item["scenario_digest"]
    )
    known = baseline(historic)
    configuration = config()
    selection = resolve(known.entries[0].id, known, configuration, entries())

    with pytest.raises(VerifyError) as caught:
        build_plan(selection, configuration, inventory(configuration))

    assert caught.value.code == "verification_coverage_changed"

    unsafe = config_without_safe()
    current = resolve(
        baseline(accepted("get_order")).entries[0].id,
        baseline(accepted("get_order")),
        unsafe,
        entries(),
    )
    with pytest.raises(VerifyError) as impeded:
        build_plan(current, unsafe, inventory(unsafe))
    assert impeded.value.code == "verification_coverage_changed"


def config_without_safe() -> Any:
    from tools_factory import config_document

    from gazua.config.models import GazuaConfig

    document = config_document()
    document["tools"]["get_order"]["safe"] = False
    return GazuaConfig.model_validate(document)
