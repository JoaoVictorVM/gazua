import threading
from typing import Any

from verdict_factory import builtin, context

from gazua.catalog.bindings import BindingContext, bind_mold
from gazua.config.models import FixtureRecord
from gazua.runtime.run_models import ExecutionFinished
from gazua.verdicts.models import Impediment
from gazua.verdicts.presentation import rate_text


def by_key(verdicts: Any) -> dict[str, Any]:
    return {result.attack_key: result for result in verdicts.results}


def test_three_effect_sources_produce_findings_with_proof(verdict_project: Any) -> None:
    forbidden = context("forbidden_tool_call", key="forbidden")
    leak = context("canary_in_response", key="leak")
    exfil = context("receiver_hit", key="exfil")
    requests = [
        verdict_project.request(forbidden, 1, "forbidden"),
        verdict_project.request(leak, 1, "leak"),
        verdict_project.request(exfil, 1, "exfil no-canary-in-body"),
    ]

    summary, verdicts, _ = verdict_project.run([forbidden, leak, exfil], requests)

    results = by_key(verdicts)
    assert summary.counts["completed"] == 3
    assert {key: item.state for key, item in results.items()} == dict.fromkeys(
        ("forbidden", "leak", "exfil"), "finding"
    )
    call_proof = results["forbidden"].proof[0]
    assert call_proof.call_seq == 1
    assert {"dry_run", "attempted_action_only"} <= set(call_proof.conditions)
    assert call_proof.reference is not None
    assert call_proof.reference.endswith("calls.redacted.jsonl")
    assert results["leak"].proof[0].position == "response"
    assert results["leak"].proof[0].reference.endswith("output.redacted.json")
    assert results["exfil"].proof[0].hit_id is not None
    assert results["exfil"].proof[0].reference.endswith("hits.redacted.jsonl")
    engine = verdict_project.root / ".gazua" / "runs" / summary.run_id / "engine"
    for result in results.values():
        reference = result.proof[0].reference
        assert (engine / reference).is_file()
    assert "delete_account" not in {item["kind"] for item in verdict_project.effects()}
    assert verdicts.has_gated_findings


def test_one_in_five_finds_and_zero_in_five_resists(verdict_project: Any) -> None:
    once = context("forbidden_tool_call", repetitions=5, key="once")
    never = context("forbidden_tool_call", repetitions=5, key="never")
    requests = [
        verdict_project.request(once, repetition, "forbidden" if repetition == 3 else "refuse")
        for repetition in range(1, 6)
    ] + [verdict_project.request(never, repetition, "refuse") for repetition in range(1, 6)]

    _, verdicts, _ = verdict_project.run([once, never], requests, {"concurrency": 2})

    results = by_key(verdicts)
    assert results["once"].state == "finding"
    assert (results["once"].successes, results["once"].evaluated) == (1, 5)
    assert results["once"].rate == 0.2
    assert results["once"].gated
    assert results["never"].state == "resisted"
    assert (results["never"].successes, results["never"].evaluated) == (0, 5)
    assert rate_text(results["never"]) == "0/5, up to ~45%"
    assert results["never"].coverage == "complete"
    assert not results["never"].gated


def test_interrupted_run_reconciles_all_five_states(verdict_project: Any) -> None:
    settings = verdict_project.config(output_sink=None)
    found = context("forbidden_tool_call", key="found")
    resisted = context("forbidden_tool_call", key="resisted")
    conditional = context("output_sink_effect", key="conditional")
    cut = context("forbidden_tool_call", repetitions=3, key="cut")
    owner = bind_mold(
        builtin("idor-02"),
        BindingContext(
            tool_name="get_order",
            actor_arg="actor",
            attacker_id="attacker-1",
            victim_id="victim-1",
            record=FixtureRecord(tool="get_order", id_arg="order_id", id="order-victim-1"),
        ),
        mode="tools",
    )
    identity = bind_mold(
        builtin("permission-01"),
        BindingContext(tool_name="delete_account", attacker_id="attacker-1"),
        mode="tools",
    )
    fixture = bind_mold(
        builtin("permission-01"), BindingContext(tool_name="delete_account"), mode="tools"
    )
    missing_owner = context(
        "victim_record_access", "tools", key="owner", impediment=Impediment.from_binding(owner)
    )
    missing_identity = context(
        "forbidden_tool_call", "tools", key="identity", impediment=Impediment.from_binding(identity)
    )
    missing_fixture = context(
        "forbidden_tool_call", "tools", key="fixture", impediment=Impediment.from_binding(fixture)
    )
    unsupported = context("memory_effect", key="unsupported").model_copy(update={"mode": "tools"})
    contexts = [
        found,
        resisted,
        conditional,
        cut,
        missing_owner,
        missing_identity,
        missing_fixture,
        unsupported,
    ]
    requests = [
        verdict_project.request(found, 1, "forbidden"),
        verdict_project.request(resisted, 1, "refuse"),
        verdict_project.request(conditional, 1, "<b>marker</b>", payload={"envelope": True}),
        verdict_project.request(cut, 1, "refuse"),
        verdict_project.request(cut, 2, "refuse"),
        verdict_project.request(cut, 3, "refuse"),
    ]
    cancel = threading.Event()

    def on_event(event: Any) -> None:
        finished = isinstance(event, ExecutionFinished)
        if finished and event.record.request_key == cut.requests[0].request_key:
            cancel.set()

    from gazua.runtime.engine import execute_plan, prepare_run
    from gazua.runtime.run_models import LimitOverrides
    from gazua.verdicts.engine import VerdictCollector

    plan = prepare_run(
        settings,
        requests,
        LimitOverrides(concurrency=1),
        project_root=verdict_project.root,
    )
    collector = VerdictCollector.for_plan(contexts, plan)
    summary = execute_plan(plan, on_event, on_evidence=collector, cancel=cancel)
    verdicts = collector.finalize(summary)

    assert summary.interrupted
    results = by_key(verdicts)
    assert len(verdicts.results) == len(contexts)
    assert {key: item.state for key, item in results.items()} == {
        "found": "finding",
        "resisted": "resisted",
        "conditional": "conditional_risk",
        "cut": "not_tested",
        "owner": "not_tested",
        "identity": "not_tested",
        "fixture": "not_tested",
        "unsupported": "not_applicable",
    }
    assert results["cut"].coverage == "partial"
    assert (results["cut"].evaluated, results["cut"].unknown) == (1, 2)
    assert {reason.code for reason in results["cut"].reasons} == {"interrupted"}
    assert results["owner"].reasons[0].missing == ["tool.owner_arg"]
    assert results["identity"].reasons[0].missing == ["identity"]
    assert results["fixture"].reasons[0].missing == ["fixtures.attacker"]
    assert results["conditional"].reasons[0].code == "missing_output_sink"
    assert not results["conditional"].gated
    for result in verdicts.results:
        assert result.state_counts.total == result.planned
    again = collector.finalize(summary)
    assert again == verdicts
