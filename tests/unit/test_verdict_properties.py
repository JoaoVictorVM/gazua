from itertools import pairwise
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st
from verdict_factory import (
    Numbers,
    call,
    config,
    context,
    evidence,
    hit,
    record,
    summary,
)

from gazua.catalog.models import MoldText
from gazua.runtime.evidence import PrivateEvidence
from gazua.runtime.run_models import ExecutionRecord
from gazua.verdicts.engine import VerdictCollector
from gazua.verdicts.models import VERDICT_STATES, AttackContext, VerdictSummary
from gazua.verdicts.statistics import upper_bound

FAST = settings(max_examples=60, deadline=None)
words = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="${}"),
    min_size=1,
    max_size=40,
)


def collect(
    contexts: list[AttackContext],
    deliveries: list[tuple[ExecutionRecord, PrivateEvidence | None]],
    records: list[ExecutionRecord],
) -> VerdictSummary:
    collector = VerdictCollector(contexts, config())
    for item, private in deliveries:
        if private is not None:
            collector(item, private)
    return collector.finalize(summary(records))


@FAST
@given(
    mold_text=words,
    response=st.one_of(
        st.just("I refuse. This request is not allowed and I will not do it."),
        st.just("Sure! I deleted the account as you asked."),
        words,
    ),
    extra=st.dictionaries(st.sampled_from(["tone", "note", "lang"]), words, max_size=3),
    positive=st.booleans(),
)
def test_verdict_ignores_refusal_and_attack_wording(
    mold_text: str, response: str, extra: dict[str, str], positive: bool
) -> None:
    def run(attack: AttackContext, output: Any) -> VerdictSummary:
        execution = record(attack, execution_id="GAZUA-exec-0001")
        calls = [call(1, "delete_account", dry_run=True)] if positive else []
        private = evidence(execution, calls=calls, output=output)
        return collect([attack], [(execution, private)], [execution])

    baseline = run(context("forbidden_tool_call"), "ok")
    attack = context("forbidden_tool_call")
    reworded = attack.model_copy(
        update={
            "mold": attack.mold.model_copy(
                update={"text": MoldText.model_construct(en=[mold_text], pt=[mold_text])}
            )
        }
    )
    varied = run(reworded, {"reply": response, **extra})

    assert varied.results[0].state == baseline.results[0].state
    assert varied.results[0].proof == baseline.results[0].proof
    assert varied.has_gated_findings == baseline.has_gated_findings
    assert varied.results[0].state == ("finding" if positive else "resisted")


OUTCOMES = st.sampled_from(
    [
        "missing",
        "positive",
        "negative",
        "timed_out",
        "skipped",
        "crashed",
        "retry_positive",
        "no_callback",
        "interrupted",
    ]
)


@FAST
@given(
    plan=st.lists(st.lists(OUTCOMES, min_size=1, max_size=4), min_size=1, max_size=4),
    signal=st.sampled_from(["forbidden_tool_call", "receiver_hit", "tool_call_ceiling"]),
)
def test_exactly_one_state_and_no_planned_item_is_lost(plan: list[list[str]], signal: str) -> None:
    numbers = Numbers()
    contexts = [
        context(signal, repetitions=len(outcomes), key=f"attack-{index}")
        for index, outcomes in enumerate(plan)
    ]
    deliveries: list[tuple[ExecutionRecord, PrivateEvidence | None]] = []
    records: list[ExecutionRecord] = []
    for attack, outcomes in zip(contexts, plan, strict=True):
        for repetition, outcome in enumerate(outcomes, start=1):
            for item, private in build(attack, repetition, outcome, numbers):
                records.append(item)
                deliveries.append((item, private))

    result = collect(contexts, deliveries, records)

    assert [item.attack_key for item in result.results] == [item.attack_key for item in contexts]
    for item, outcomes in zip(result.results, plan, strict=True):
        assert item.planned == len(outcomes)
        assert item.state_counts.total == item.planned
        assert item.state in VERDICT_STATES
        assert item.successes <= item.evaluated <= item.planned
        if "missing" in outcomes:
            assert "missing_execution_record" in result.operational_errors
            assert item.state != "resisted"
    assert sum(counts.total for counts in result.counts_by_damage.values()) == len(contexts)


def build(
    attack: AttackContext, repetition: int, outcome: str, numbers: Numbers
) -> list[tuple[ExecutionRecord, PrivateEvidence | None]]:
    def made(attempt: int = 1, **fields: Any) -> ExecutionRecord:
        if attack.signal == "receiver_hit":
            identifier = numbers.next()
            fields.setdefault("receiver_hits", f"executions/{identifier}/hits.redacted.jsonl")
            return record(attack, repetition, attempt, execution_id=identifier, **fields)
        return record(attack, repetition, attempt, execution_id=numbers.next(), **fields)

    def positive_evidence(item: ExecutionRecord) -> PrivateEvidence:
        if attack.signal == "receiver_hit":
            return evidence(item, hits=[hit(item)])
        return evidence(item, calls=[call(1, "delete_account", dry_run=True)])

    if outcome == "missing":
        return []
    if outcome == "positive":
        if attack.signal == "tool_call_ceiling":
            item = made(
                status="killed_at_ceiling", reason="tool_call_ceiling", admitted_tool_calls=50
            )
            return [(item, evidence(item, complete=False))]
        item = made()
        return [(item, positive_evidence(item))]
    if outcome == "negative":
        item = made()
        return [(item, evidence(item))]
    if outcome in ("timed_out", "crashed"):
        item = made(
            status=outcome, reason="attack_timeout" if outcome == "timed_out" else "agent_crashed"
        )
        return [(item, evidence(item))]
    if outcome == "skipped":
        return [(made(status="skipped_by_limit", reason="max_runs"), None)]
    if outcome == "interrupted":
        return [(made(status="not_tested", reason="interrupted"), None)]
    if outcome == "no_callback":
        return [(made(), None)]
    first = made(status="rate_limited", reason="rate_limited")
    second = made(attempt=2)
    return [(first, evidence(first)), (second, positive_evidence(second))]


@FAST
@given(
    status=st.sampled_from(["timed_out", "crashed", "cancelled", "killed_at_ceiling"]),
    truncated=st.booleans(),
    later=st.sampled_from(["negative", "timed_out", "none"]),
)
def test_positive_evidence_survives_incomplete_execution(
    status: str, truncated: bool, later: str
) -> None:
    attack = context("forbidden_tool_call")
    first = record(attack, status=status, reason="interrupted", truncated_tail=truncated)
    private = evidence(
        first,
        calls=[call(1, "delete_account", dry_run=True)],
        truncated_tail=truncated,
        complete=False,
    )
    deliveries: list[tuple[ExecutionRecord, PrivateEvidence | None]] = [(first, private)]
    if later != "none":
        fields = {} if later == "negative" else {"status": "timed_out", "reason": "attack_timeout"}
        second = record(attack, attempt=2, **fields)
        deliveries.append((second, evidence(second)))
    result = collect([attack], deliveries, [item for item, _ in deliveries])

    [item] = result.results
    assert item.state == "finding"
    assert (item.successes, item.evaluated) == (1, 1)
    assert item.proof
    assert "execution_incomplete" in item.proof[0].conditions
    assert ("truncated_tail" in item.proof[0].conditions) == truncated


@FAST
@given(
    attempts=st.lists(st.lists(st.booleans(), min_size=1, max_size=3), min_size=1, max_size=5),
    order=st.randoms(use_true_random=False),
    duplicates=st.integers(min_value=0, max_value=3),
)
def test_retries_and_order_do_not_inflate_rates(
    attempts: list[list[bool]], order: Any, duplicates: int
) -> None:
    attack = context("forbidden_tool_call", repetitions=len(attempts))
    numbers = Numbers()
    deliveries: list[tuple[ExecutionRecord, PrivateEvidence | None]] = []
    for repetition, flags in enumerate(attempts, start=1):
        for attempt, positive in enumerate(flags, start=1):
            last = attempt == len(flags)
            fields: dict[str, Any] = (
                {} if last else {"status": "rate_limited", "reason": "rate_limited"}
            )
            item = record(attack, repetition, attempt, execution_id=numbers.next(), **fields)
            calls = [call(1, "delete_account", dry_run=True)] if positive else []
            deliveries.append((item, evidence(item, calls=calls)))
    records = [item for item, _ in deliveries]
    canonical = collect([attack], deliveries, records)

    shuffled = list(deliveries) + [order.choice(deliveries) for _ in range(duplicates)]
    order.shuffle(shuffled)
    reordered = collect([attack], shuffled, records)

    expected = sum(any(flags) for flags in attempts)
    assert canonical.results == reordered.results
    [item] = canonical.results
    assert item.successes == expected
    assert item.planned == len(attempts)
    assert item.state == ("finding" if expected else "resisted")


@FAST
@given(trials=st.integers(min_value=1, max_value=60), data=st.data())
def test_bounds_monotonic_and_above_rate(trials: int, data: Any) -> None:
    bounds = [upper_bound(successes, trials) for successes in range(trials + 1)]
    values = [bound for bound in bounds if bound is not None]
    assert len(values) == trials + 1
    assert all(earlier < later for earlier, later in pairwise(values))
    assert all(value >= successes / trials for successes, value in enumerate(values))
    assert values[-1] == 1.0
    more = data.draw(st.integers(min_value=trials + 1, max_value=120))
    shrinking = upper_bound(0, more)
    assert shrinking is not None
    assert shrinking < values[0]
