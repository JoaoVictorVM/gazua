from typing import Any

MARKER = '<b data-gazua="marker">GAZUA-OUTPUT-MARKER</b>'


def states(result: Any) -> dict[str, str]:
    contexts = {context.attack_key: context for context in result.contexts}
    return {
        contexts[item.attack_key].tool_name: item.state
        for item in result.verdicts.results
        if contexts[item.attack_key].tool_name in ("get_order", "archive_order")
    }


def test_sink_markers_and_missing_sink_follow_verdict_contract(tools_project: Any) -> None:
    shown = tools_project.run("output-01")

    assert states(shown) == {"archive_order": "finding", "get_order": "finding"}
    finding = next(item for item in shown.verdicts.results if item.state == "finding")
    assert {"test_sink_only", "synthetic_marker"} <= set(finding.proof[0].conditions)
    sunk = [item["value"] for item in tools_project.effects() if item["kind"] == "sink"]
    assert sunk
    assert set(sunk) == {MARKER}
    assert not any(
        item["kind"] in ("get_order", "archive_order", "refund") for item in tools_project.effects()
    )

    tools_project.harden()
    (tools_project.root / "async_sink").write_text("x", encoding="utf-8")
    escaped = tools_project.run("output-01")
    assert set(states(escaped).values()) == {"resisted"}
    assert escaped.exit_code == 0

    (tools_project.root / "broken_sink").write_text("x", encoding="utf-8")
    broken = tools_project.run("output-01")
    assert set(states(broken).values()) == {"not_tested"}
    assert "sink_error" in broken.verdicts.operational_errors
    assert broken.exit_code == 2
    assert "private detail" not in broken.model_dump_json()

    tools_project.write(output_sink=None)
    missing = tools_project.run("output-01")
    assert set(states(missing).values()) == {"conditional_risk"}
    reasons = {
        reason.code
        for item in missing.verdicts.results
        if item.state == "conditional_risk"
        for reason in item.reasons
    }
    assert reasons == {"missing_output_sink"}
    assert not missing.has_gated_findings
    assert missing.exit_code == 0
