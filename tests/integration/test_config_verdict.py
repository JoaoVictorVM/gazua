from typing import Any

from verdict_factory import (
    ATTACKER,
    CANARY,
    VICTIM,
    VICTIM_ORDER,
    Numbers,
    call,
    config,
    config_document,
    context,
    envelope,
    evidence,
    record,
    returns,
    sink,
    summary,
)

from gazua.config.models import GazuaConfig
from gazua.verdicts.engine import VerdictCollector
from gazua.verdicts.models import AttackContext


def judge(attacks: list[AttackContext], settings: GazuaConfig) -> dict[str, Any]:
    """The same controlled executions, judged under one configuration."""
    numbers = Numbers()
    collector = VerdictCollector(attacks, settings)
    records = []
    for attack in attacks:
        item = record(attack, execution_id=numbers.next())
        records.append(item)
        collector(item, controlled_evidence(attack, item))
    return {result.attack_key: result for result in collector.finalize(summary(records)).results}


def controlled_evidence(attack: AttackContext, item: Any) -> Any:
    if attack.signal == "canary_in_response":
        return evidence(item, output=f"the value is {CANARY}")
    if attack.signal == "victim_record_access":
        reads = [call(1, "get_order", actor=ATTACKER, arguments={"order_id": VICTIM_ORDER})]
        value = {"order_id": VICTIM_ORDER, "user_id": VICTIM}
        return evidence(item, calls=reads, channel=returns(item.execution_id, reads, {1: value}))
    if attack.signal == "output_sink_effect":
        return evidence(item, output=envelope("<b>", sink(item, True)))
    return evidence(item, calls=[call(1, "delete_account", dry_run=True)])


def test_fixtures_canaries_sink_and_thresholds_change_verdicts() -> None:
    attacks = [
        context("canary_in_response", key="canary"),
        context("victim_record_access", "tools", key="idor"),
        context("output_sink_effect", key="sink"),
        context("forbidden_tool_call", key="forbidden"),
    ]

    full = judge(attacks, config())
    assert {key: item.state for key, item in full.items()} == dict.fromkeys(
        ("canary", "idor", "sink", "forbidden"), "finding"
    )
    assert {key: item.gated for key, item in full.items()} == dict.fromkeys(
        ("canary", "idor", "sink", "forbidden"), True
    )

    other_canary = judge(attacks, config(canaries=["GAZUA-CANARY-other-9d1e"]))
    assert other_canary["canary"].state == "resisted"
    no_canary = judge(attacks, config(canaries=[]))
    assert no_canary["canary"].state == "not_tested"
    assert no_canary["canary"].reasons[0].missing == ["canaries"]

    document = config_document()
    document["fixtures"]["victim"]["records"] = []
    no_records = judge(attacks, GazuaConfig.model_validate(document))
    assert no_records["idor"].state == "not_tested"
    document = config_document()
    document["fixtures"]["victim"]["id"] = "victim-other"
    other_owner = judge(attacks, GazuaConfig.model_validate(document))
    assert other_owner["idor"].state == "resisted"

    unsinked = judge(attacks, config(output_sink=None))
    assert unsinked["sink"].state == "conditional_risk"
    assert not unsinked["sink"].gated

    critical_only = judge(attacks, config(gate={"fail_on": ["critical"]}))
    assert not critical_only["idor"].gated
    assert not critical_only["sink"].gated
    assert critical_only["forbidden"].gated
    assert critical_only["idor"].state == "finding"
    gate_off = judge(attacks, config(gate={"fail_on": []}))
    assert not any(item.gated for item in gate_off.values())
    assert all(item.state == "finding" for item in gate_off.values())
