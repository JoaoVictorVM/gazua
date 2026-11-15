from dataclasses import dataclass

from baseline_factory import FINDING_A, FINDING_B, FINDING_C, baseline, entry
from report_factory import document

from gazua.baseline.comparison import compare, effective_exit, summary_text

DIGEST = "d" * 64


@dataclass(frozen=True)
class Seen:
    id: str
    gated: bool = True


def test_known_gated_finding_is_suppressed() -> None:
    result = compare([Seen(FINDING_A)], baseline(entry(FINDING_A)), DIGEST)

    [item] = result.observed
    assert (item.status, item.native_gated, item.effective_gated) == ("open", True, False)
    assert not result.has_new_gated_findings
    assert effective_exit(1, result) == 0
    assert summary_text(result) == "1 known finding, 0 new"


def test_new_and_recurrent_findings_are_gated() -> None:
    known = baseline(entry(FINDING_A), entry(FINDING_B, status="closed"))

    result = compare([Seen(FINDING_A), Seen(FINDING_B), Seen(FINDING_C)], known, DIGEST)

    states = {item.finding_id: (item.status, item.regression) for item in result.observed}
    assert states == {
        FINDING_A: ("open", False),
        FINDING_B: ("new", True),
        FINDING_C: ("new", False),
    }
    recurrence = next(item for item in result.entries if item.finding_id == FINDING_B)
    assert recurrence.baseline_status == "closed"
    assert result.has_new_gated_findings
    assert (result.observed_known, result.observed_new) == (1, 2)
    assert effective_exit(1, result) == 1
    assert effective_exit(2, result) == 2
    assert "closed before and found again" in summary_text(result)


def test_gate_fail_on_and_empty_gate_are_respected() -> None:
    ungated = compare([Seen(FINDING_C, gated=False)], baseline(entry(FINDING_A)), DIGEST)

    assert ungated.observed_new == 1
    assert not ungated.has_new_gated_findings
    assert effective_exit(0, ungated) == 0
    [unobserved] = ungated.unobserved
    assert (unobserved.finding_id, unobserved.status) == (FINDING_A, "open")
    assert not unobserved.effective_gated

    built = document()
    [finding] = built.findings
    known = compare(built.findings, baseline(entry(finding.id)), DIGEST)
    assert built.verdicts.has_gated_findings
    assert effective_exit(built.report_exit_code, known) == 0
    assert effective_exit(2, known) == 2


def test_unobserved_entries_keep_state_and_never_gate() -> None:
    known = baseline(entry(FINDING_A), entry(FINDING_B, status="closed"))

    result = compare([], known, DIGEST)

    assert [(item.finding_id, item.status, item.observed) for item in result.entries] == [
        (FINDING_A, "open", False),
        (FINDING_B, "closed", False),
    ]
    assert (result.observed_known, result.observed_new) == (0, 0)
    assert summary_text(result) == "0 known findings, 0 new"
