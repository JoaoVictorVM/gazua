from typing import Any


def results_by_mold(result: Any) -> dict[str, list[Any]]:
    grouped: dict[str, list[Any]] = {}
    for item in result.verdicts.results:
        grouped.setdefault(item.mold_id, []).append(item)
    return grouped


def test_vulnerable_finds_hardened_stays_quiet(tools_project: Any) -> None:
    vulnerable = tools_project.run("idor-01")

    [found] = vulnerable.verdicts.results
    assert found.state == "finding"
    assert found.gated
    assert vulnerable.exit_code == 1
    [proof] = found.proof
    assert proof.signal == "victim_record_access"
    assert proof.call_seq is not None
    assert "fixture_specific" in proof.conditions
    assert proof.facts["tool"] == "get_order"
    assert proof.facts["id_path"] == ["order_id"]
    assert proof.facts["owner_path"] == ["user_id"]
    calls = [item for item in tools_project.effects() if item["kind"] == "get_order"]
    assert calls == [{"kind": "get_order", "order_id": "order-victim-1", "actor": "attacker-1"}]

    tools_project.harden()
    hardened = tools_project.run("idor-01")

    [quiet] = hardened.verdicts.results
    assert quiet.state == "resisted"
    assert quiet.coverage == "complete"
    assert not hardened.has_gated_findings
    assert hardened.exit_code == 0
    assert found.attack_key == quiet.attack_key


def test_no_identity_is_not_tested(tools_project: Any) -> None:
    document = tools_project.document()
    document["tools"]["get_order"].pop("actor_arg")
    tools_project.write(tools=document["tools"])

    result = tools_project.run()

    grouped = results_by_mold(result)
    for mold_id in ("idor-01", "idor-02", "idor-03"):
        [item] = grouped[mold_id]
        assert item.state == "not_tested"
        assert [reason.missing for reason in item.reasons] == [["identity"]]
    assert not any(
        effect["kind"] == "get_order" and effect["actor"] is not None
        for effect in tools_project.effects()
    )
    assert not any(effect["kind"] == "entrypoint_called" for effect in tools_project.effects())
