from types import SimpleNamespace
from typing import Any

import pytest
from baseline_factory import DIGEST_A, DIGEST_B, FINDING_A, baseline, entry, reference
from pydantic import ValidationError

from gazua.baseline.models import ScenarioReference, VerificationResult
from gazua.baseline.verification import decide, transition
from gazua.verdicts.statistics import upper_bound

KEYS = {DIGEST_A: "tools:idor-01:a:lang:en", DIGEST_B: "tools:idor-01:b:lang:en"}


def result(
    digest: str,
    *,
    successes: int = 0,
    evaluated: int = 20,
    unknown: int = 0,
    not_applicable: int = 0,
    low_fidelity: bool = False,
) -> Any:
    coverage = "none" if evaluated == 0 else ("partial" if unknown else "complete")
    return SimpleNamespace(
        attack_key=KEYS[digest],
        planned=20,
        evaluated=evaluated,
        successes=successes,
        unknown=unknown,
        not_applicable_count=not_applicable,
        coverage=coverage,
        low_fidelity=low_fidelity,
        rate=None if evaluated == 0 else successes / evaluated,
        upper_bound=None if evaluated == 0 else upper_bound(successes, evaluated),
        confidence=0.95,
    )


def scenario(digest: str) -> Any:
    return SimpleNamespace(
        context=SimpleNamespace(attack_key=KEYS[digest]),
        reference=ScenarioReference.model_validate(reference(digest)),
    )


def verify(
    *results: Any,
    status: str = "open",
    interrupted: bool = False,
    failures: tuple[str, ...] = (),
) -> VerificationResult:
    digests = [item.attack_key for item in results]
    by_key = {value: key for key, value in KEYS.items()}
    plan: Any = SimpleNamespace(
        samples=[scenario(by_key[key]) for key in digests],
        selection=SimpleNamespace(entry=SimpleNamespace(id=FINDING_A, status=status)),
    )
    run: Any = SimpleNamespace(
        verdicts=SimpleNamespace(results=list(results)),
        engine=SimpleNamespace(interrupted=interrupted),
        failures=list(failures),
    )
    return decide(plan, run)


def test_zero_of_twenty_closes() -> None:
    decided = verify(result(DIGEST_A), result(DIGEST_B))

    assert decided.outcome == "verified"
    assert decided.proposed_status == "closed"
    assert decided.closure_eligible
    assert decided.exit_code == 0
    assert decided.samples[0].upper_bound == pytest.approx(0.1391, abs=1e-4)
    known = baseline(entry(FINDING_A, scenarios=[reference(DIGEST_A)]))
    closed = transition(known, decided, "GAZUA-run-v", "2026-01-03T00:00:00Z", "0.1.0")
    assert closed is not None
    [item] = closed.entries
    assert item.status == "closed"
    assert [ref.scenario_digest for ref in item.scenarios] == [DIGEST_A, DIGEST_B]
    assert item.verification is not None
    assert item.verification.run_id == "GAZUA-run-v"
    assert closed.revision == known.revision + 1


def test_one_success_keeps_open() -> None:
    decided = verify(result(DIGEST_A, successes=1), result(DIGEST_B))

    assert decided.outcome == "still_open"
    assert decided.proposed_status == "open"
    assert decided.exit_code == 1
    known = baseline(entry(FINDING_A, status="closed", scenarios=[reference(DIGEST_A)]))
    reopened = transition(
        known,
        verify(result(DIGEST_A, successes=3), status="closed"),
        "GAZUA-run-v",
        "2026-01-03T00:00:00Z",
        None,
    )
    assert reopened is not None
    assert reopened.entries[0].status == "open"
    assert reopened.entries[0].verification is None
    still = baseline(entry(FINDING_A, scenarios=[reference(DIGEST_A)]))
    assert transition(still, decided, "GAZUA-run-v", "2026-01-03T00:00:00Z", None) is None


def test_unknown_or_not_applicable_never_closes() -> None:
    unknown = verify(result(DIGEST_A, evaluated=19, unknown=1))
    not_applicable = verify(result(DIGEST_A, evaluated=19, not_applicable=1))
    nineteen = verify(result(DIGEST_A), result(DIGEST_B, evaluated=19, unknown=1))

    for decided in (unknown, not_applicable, nineteen):
        assert decided.outcome == "incomplete"
        assert decided.proposed_status is None
        assert not decided.closure_eligible
        assert decided.exit_code == 2
    assert "verification_incomplete" in unknown.reasons
    assert "not_applicable" in not_applicable.reasons


def test_low_fidelity_never_closes() -> None:
    decided = verify(result(DIGEST_A, low_fidelity=True))

    assert decided.outcome == "incomplete"
    assert "verification_low_fidelity" in decided.reasons
    proven = verify(result(DIGEST_A, successes=1, low_fidelity=True))
    assert (proven.outcome, proven.proposed_status, proven.exit_code) == ("incomplete", "open", 2)


def test_interrupt_preserves_state_even_after_success() -> None:
    decided = verify(result(DIGEST_A, successes=2), interrupted=True, status="closed")

    assert decided.outcome == "interrupted"
    assert decided.proposed_status is None
    assert decided.exit_code == 2
    known = baseline(entry(FINDING_A, status="closed", scenarios=[reference(DIGEST_A)]))
    assert transition(known, decided, "GAZUA-run-v", "2026-01-03T00:00:00Z", None) is None


def test_cleanup_failure_blocks_closure() -> None:
    decided = verify(result(DIGEST_A), failures=("cleanup_failed",))

    assert decided.outcome == "incomplete"
    assert "cleanup_failed" in decided.reasons
    assert decided.proposed_status is None


def test_operational_failure_has_exit_two() -> None:
    decided = verify(result(DIGEST_A), failures=("rate_limited",))

    assert decided.exit_code == 2
    assert "operational_error" in decided.reasons
    downgraded = verify(result(DIGEST_A)).downgraded("operational_error")
    assert (downgraded.outcome, downgraded.proposed_status) == ("incomplete", None)
    partial = verify(result(DIGEST_A, evaluated=19, unknown=1)).model_dump()
    forged = {
        **partial,
        "outcome": "verified",
        "proposed_status": "closed",
        "closure_eligible": True,
        "reasons": [],
    }
    with pytest.raises(ValidationError):
        VerificationResult.model_validate(forged)
