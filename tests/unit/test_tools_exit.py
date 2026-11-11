from typing import Any

from verdict_factory import call, config, context, evidence, record, summary

from gazua.modes.tools import exit_code_for, operational_failures
from gazua.verdicts.engine import VerdictCollector


def judged(
    contexts: list[Any], records: list[Any], evidences: dict[str, Any], **fields: Any
) -> Any:
    collector = VerdictCollector(contexts, config())
    for item in records:
        if item.execution_id in evidences:
            collector(item, evidences[item.execution_id])
    run = summary(records, **fields)
    verdicts = collector.finalize(run)
    failures = operational_failures(run, verdicts, contexts)
    return failures, exit_code_for(failures, verdicts), verdicts


def forbidden_finding() -> tuple[Any, Any, Any]:
    attack = context("forbidden_tool_call", "tools", key="forbidden")
    done = record(attack)
    proof = evidence(done, calls=[call(1, "delete_account")])
    return attack, done, proof


def test_operational_error_precedes_gated_finding() -> None:
    attack, done, proof = forbidden_finding()
    crashed_attack = context("sensitive_tool_call", "tools", key="crashed")
    crashed = record(crashed_attack, status="crashed", reason="agent_crashed")

    failures, code, verdicts = judged(
        [attack, crashed_attack], [done, crashed], {done.execution_id: proof}
    )

    assert verdicts.has_gated_findings
    assert failures == ["agent_crashed"]
    assert code == 2
    _, clean_code, _ = judged([attack], [done], {done.execution_id: proof})
    assert clean_code == 1
    resisted = context("forbidden_tool_call", "tools", key="calm")
    calm = record(resisted)
    assert judged([resisted], [calm], {calm.execution_id: evidence(calm)})[1] == 0
    for status, reason in (("timed_out", "attack_timeout"), ("reset_failed", "reset_failed")):
        failed = record(resisted, status=status, reason=reason)
        assert judged([resisted], [failed], {})[1] == 2
    interrupted = record(resisted, status="cancelled", reason="interrupted")
    failures, code, _ = judged([resisted], [interrupted], {}, interrupted=True)
    assert code == 2
    assert "interrupted" in failures


def test_limits_are_not_execution_errors() -> None:
    attack, done, proof = forbidden_finding()
    skipped_attack = context("sensitive_tool_call", "tools", key="later")
    skipped = record(skipped_attack, status="skipped_by_limit", reason="max_runs")
    budget = context("sensitive_tool_call", "tools", key="budget")
    stopped = record(budget, status="cancelled", reason="max_cost")
    retried = context("sensitive_tool_call", "tools", key="retried")
    first = record(retried, status="rate_limited", reason="rate_limited")
    second = record(retried, attempt=2)

    failures, code, verdicts = judged(
        [attack, skipped_attack, budget, retried],
        [done, skipped, stopped, first, second],
        {done.execution_id: proof, second.execution_id: evidence(second)},
    )

    assert failures == []
    assert code == 1
    states = {result.attack_key: result.state for result in verdicts.results}
    assert states["later"] == "not_tested"
    terminal = context("sensitive_tool_call", "tools", key="terminal")
    limited = record(terminal, status="rate_limited", reason="rate_limited")
    assert judged([terminal], [limited], {})[0] == ["rate_limited"]


def test_expected_ceiling_uses_verdict_gate() -> None:
    expected = context("tool_call_ceiling", "tools", key="spending")
    killed = record(
        expected, status="killed_at_ceiling", reason="tool_call_ceiling", admitted_tool_calls=50
    )
    failures, code, verdicts = judged([expected], [killed], {killed.execution_id: evidence(killed)})

    assert failures == []
    [result] = verdicts.results
    assert result.state == "finding"
    assert result.gated is False
    assert code == 0

    unexpected = context("forbidden_tool_call", "tools", key="forbidden")
    stray = record(
        unexpected, status="killed_at_ceiling", reason="tool_call_ceiling", admitted_tool_calls=50
    )
    failures, code, _ = judged([unexpected], [stray], {stray.execution_id: evidence(stray)})
    assert failures == ["unexpected_tool_call_ceiling"]
    assert code == 2
