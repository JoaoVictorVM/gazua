from baseline_factory import (
    DIGEST_A,
    DIGEST_B,
    FINDING_A,
    FINDING_B,
    FINDING_C,
    baseline,
    entry,
    reference,
)
from report_factory import FOUND, RESISTED, document, five_states
from verdict_factory import context

from gazua.baseline.models import ScenarioReference, scenario_digest
from gazua.baseline.storage import AcceptedFinding, accepted_findings, merge_findings


def accepted(identifier: str, *digests: str, language: str = "en") -> AcceptedFinding:
    return AcceptedFinding(
        identifier,
        "tools",
        tuple(
            ScenarioReference.model_validate(reference(item, language))
            for item in (digests or (DIGEST_A,))
        ),
    )


def test_merge_preserves_absent_open_and_closed() -> None:
    existing = baseline(entry(FINDING_A), entry(FINDING_B, status="closed"), revision=4)

    merged = merge_findings(existing, [accepted(FINDING_C)], "0.1.0")

    statuses = {item.id: item.status for item in merged.document.entries}
    assert statuses == {FINDING_A: "open", FINDING_B: "closed", FINDING_C: "open"}
    assert merged.changed
    assert merged.document.revision == 5
    assert (merged.accepted, merged.preserved, merged.reopened) == (1, 2, 0)
    closed = merged.document.entry(FINDING_B)
    assert closed is not None
    assert closed.verification is not None

    nothing = merge_findings(existing, [], "0.1.0")
    assert not nothing.changed
    assert nothing.document is existing


def test_accepting_recurrence_reopens_and_clears_receipt() -> None:
    existing = baseline(entry(FINDING_A, status="closed"))

    merged = merge_findings(existing, [accepted(FINDING_A, DIGEST_B)], "0.1.0")

    reopened = merged.document.entry(FINDING_A)
    assert reopened is not None
    assert reopened.status == "open"
    assert reopened.verification is None
    assert [item.scenario_digest for item in reopened.scenarios] == [DIGEST_A, DIGEST_B]
    assert merged.reopened == 1


def test_merge_unions_all_group_scenarios() -> None:
    second = context("victim_record_access", "tools", key="tools:idor-02:second-record")
    built = document(five_states(extra_found=[second]))
    [finding] = built.findings

    [found] = accepted_findings(built)

    digests = {item.scenario_digest for item in found.scenarios}
    assert found.id == finding.id
    assert scenario_digest(FOUND) in digests
    assert scenario_digest("tools:idor-02:second-record") in digests
    # The resisted scenario of the same mold and tool is covered too.
    assert scenario_digest(RESISTED) in digests
    assert {item.language for item in found.scenarios} == {"en"}

    created = merge_findings(None, [found], "0.1.0")
    entry_found = created.document.entry(finding.id)
    assert entry_found is not None
    assert len(entry_found.scenarios) == len(found.scenarios)
    assert created.created
    assert created.document.revision == 1
    widened = merge_findings(created.document, [accepted(finding.id, "f" * 64)], "0.1.0")
    entry_widened = widened.document.entry(finding.id)
    assert entry_widened is not None
    assert len(entry_widened.scenarios) == len(found.scenarios) + 1
