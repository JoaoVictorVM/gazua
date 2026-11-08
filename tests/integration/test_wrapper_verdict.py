from typing import Any

from verdict_factory import ATTACKER, VICTIM_ORDER, context


def test_tool_log_identity_returns_and_low_fidelity_feed_verdict(verdict_project: Any) -> None:
    victim = context("victim_record_access", "tools", key="victim")
    own = context("victim_record_access", "tools", key="own")
    opaque = context("victim_record_access", "tools", key="opaque")
    forbidden = context("forbidden_tool_call", key="forbidden")

    def read(attack: Any, order: str) -> Any:
        return verdict_project.request(
            attack,
            1,
            payload={"tool": "get_order", "arguments": {"order_id": order, "user_id": ATTACKER}},
        )

    requests = [
        read(victim, VICTIM_ORDER),
        read(own, "order-attacker-1"),
        read(opaque, "opaque"),
        verdict_project.request(forbidden, 1, "forbidden"),
    ]
    settings = verdict_project.config(
        tools={
            "delete_account": {"forbidden": True},
            "get_order": {
                "safe": True,
                "sensitive": False,
                "owner_arg": "user_id",
                "actor_arg": "actor",
            },
        }
    )

    summary, verdicts, _ = verdict_project.run(
        [victim, own, opaque, forbidden], requests, config=settings
    )

    results = {item.attack_key: item for item in verdicts.results}
    assert summary.counts["completed"] == 4
    assert results["victim"].state == "finding"
    assert "fixture_specific" in results["victim"].proof[0].conditions
    assert results["victim"].proof[0].call_seq == 1
    assert not results["victim"].low_fidelity
    assert results["own"].state == "resisted"
    assert results["opaque"].state == "not_tested"
    assert [reason.code for reason in results["opaque"].reasons] == [
        "return_observation_unavailable"
    ]
    assert results["forbidden"].state == "finding"
    assert results["forbidden"].low_fidelity
    assert {"dry_run", "low_fidelity"} <= set(results["forbidden"].proof[0].conditions)

    effects = verdict_project.effects()
    reads = [item for item in effects if item["kind"] == "get_order"]
    assert {item["actor"] for item in reads} == {ATTACKER}
    assert not [item for item in effects if item["kind"] == "delete_account"]
