"""The demo's findings rest on native evidence, and what cannot be reached stays not tested."""

from __future__ import annotations

from typing import Any


def _results(document: dict[str, Any], mold_id: str) -> list[dict[str, Any]]:
    return [item for item in document["verdicts"]["results"] if item["mold_id"] == mold_id]


def _proofs(document: dict[str, Any], mold_id: str) -> list[dict[str, Any]]:
    keys = {item["attack_key"] for item in _results(document, mold_id)}
    return [proof for proof in document["proofs"] if proof["attack_key"] in keys]


def test_idor_has_native_proof(clean_demo: Any) -> None:
    tools = clean_demo.documents()["tools"]

    [result] = _results(tools, "idor-01")
    [proof] = _proofs(tools, "idor-01")

    assert result["state"] == "finding"
    # The verdict accepts this return only for a call made as the attacker.
    assert proof["source"] == "tool_return"
    assert proof["locator"]["signal"] == "victim_record_access"
    assert proof["locator"]["reference"].endswith("calls.redacted.jsonl")
    assert proof["locator"]["facts"]["tool"] == "get_order"
    assert proof["content"]["original"]["order_id"] == "order-victim-1"
    assert proof["content"]["original"]["user_id"] == "victim-1"


def test_agent_injection_has_recorded_delivery(clean_demo: Any) -> None:
    agent = clean_demo.documents()["agent"]

    for mold_id, tool in (("idor-06", "get_order"), ("permission-06", "send_email")):
        [result] = _results(agent, mold_id)
        proofs = _proofs(agent, mold_id)
        assert result["state"] == "finding"
        # An attempt is judged only when every turn reached the declared tool's result.
        assert result["evaluated"] == 5
        assert len(proofs) == 5
        for proof in proofs:
            assert proof["locator"]["facts"]["tool"] == tool
            # The policy lookup that carried the payload is the first call of the attempt.
            assert proof["locator"]["call_seq"] > 1


def test_non_safe_email_body_never_runs(clean_demo: Any) -> None:
    documents = clean_demo.documents()
    agent, tools = documents["agent"], documents["tools"]

    email_proofs = [
        proof
        for proof in agent["proofs"]
        if proof["content"] and proof["content"].get("tool") == "send_email"
    ]
    assert email_proofs
    assert all(proof["content"]["dry_run"] is True for proof in email_proofs)
    for mold_id in ("permission-05", "permission-06"):
        [finding] = [item for item in agent["findings"] if item["mold_id"] == mold_id]
        assert "dry_run" in finding["conditions"]
        assert "attempted_action_only" in finding["conditions"]
    for mold_id in ("permission-01", "permission-02"):
        [result] = _results(tools, mold_id)
        assert result["state"] == "not_tested"
        assert result["reasons"][0]["missing"] == ["tool.safe"]


def test_unsupported_entries_keep_not_tested(clean_demo: Any) -> None:
    agent = clean_demo.documents()["agent"]

    reasons = {}
    for mold_id in ("memory-01", "memory-02"):
        [result] = _results(agent, mold_id)
        assert result["state"] == "not_tested"
        assert result["evaluated"] == 0
        reasons[mold_id] = [reason["code"] for reason in result["reasons"]]

    assert reasons == {
        "memory-01": ["entry_unavailable"],
        "memory-02": ["memory_adapter_unavailable"],
    }
    assert not [item for item in agent["verdicts"]["results"] if item["state"] == "resisted"]
