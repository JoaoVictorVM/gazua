from typing import Any

from verdict_factory import CANARY, context


def sink_requests(project: Any, attack: Any, cases: list[str]) -> list[Any]:
    return [
        project.request(
            attack,
            index,
            "echo <b>marker</b>",
            payload={"envelope": True, "sink": case, "marker_id": attack.marker_id},
        )
        for index, case in enumerate(cases, start=1)
    ]


def states(verdicts: Any) -> dict[str, tuple[str, list[str]]]:
    return {
        result.attack_key: (result.state, [reason.code for reason in result.reasons])
        for result in verdicts.results
    }


def test_sink_effect_missing_sink_and_gate(verdict_project: Any) -> None:
    attacks = {
        case: context("output_sink_effect", key=case) for case in ("show", "escape", "invalid")
    }
    requests = [
        request
        for case, attack in attacks.items()
        for request in sink_requests(verdict_project, attack, [case])
    ]
    _, verdicts, _ = verdict_project.run(list(attacks.values()), requests)

    assert states(verdicts) == {
        "show": ("finding", []),
        "escape": ("resisted", []),
        "invalid": ("not_tested", ["sink_result_invalid"]),
    }
    found = verdicts.results[0]
    assert found.gated
    assert {"test_sink_only", "synthetic_marker"} <= set(found.proof[0].conditions)
    assert found.proof[0].facts["sink_proof"] == {
        "marker_id": "markup_marker",
        "observed": "unescaped_markup",
    }
    assert "sink_result_invalid" in verdicts.operational_errors

    unsinked = context("output_sink_effect", key="unsinked")
    _, missing, _ = verdict_project.run(
        [unsinked],
        sink_requests(verdict_project, unsinked, ["show"]),
        config=verdict_project.config(output_sink=None),
    )
    assert states(missing) == {"unsinked": ("conditional_risk", ["missing_output_sink"])}
    assert not missing.has_gated_findings
    assert missing.results[0].rate is None


def test_sync_async_timeout_and_crash_are_isolated(verdict_project: Any) -> None:
    attack = context("output_sink_effect", repetitions=5, key="sink")
    cases = ["async", "hang", "crash", "exit", "escape"]
    requests = sink_requests(verdict_project, attack, cases)

    summary, verdicts, _ = verdict_project.run([attack], requests, {"timeout": 4})

    statuses = [(record.status, record.reason) for record in summary.records]
    assert statuses == [
        ("completed", None),
        ("timed_out", "attack_timeout"),
        ("completed", None),
        ("crashed", "agent_crashed"),
        ("completed", None),
    ]
    [result] = verdicts.results
    assert result.state == "finding"
    assert result.state_counts.model_dump() == {
        "finding": 1,
        "conditional_risk": 0,
        "resisted": 1,
        "not_tested": 3,
        "not_applicable": 0,
    }
    assert {reason.code for reason in result.reasons} == {
        "attack_timeout",
        "sink_error",
        "agent_crashed",
    }
    assert "sink_error" in result.operational_errors
    engine = verdict_project.root / ".gazua" / "runs" / summary.run_id / "engine"
    for path in engine.rglob("*"):
        if path.is_file():
            content = path.read_text(encoding="utf-8", errors="replace")
            assert "private detail" not in content
            assert CANARY not in content
    assert "private detail" not in verdicts.model_dump_json()
