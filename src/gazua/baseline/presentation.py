"""Fixed sentences for the baseline comparison and the verification, in the terminal and reports.

Every value shown is an id, a count, a state or a rate; no attack text is read here. A report
states what was decided when it was written, never the current content of the baseline file.
"""

from __future__ import annotations

from dataclasses import dataclass

from gazua.baseline.comparison import summary_text
from gazua.baseline.models import (
    BaselineComparison,
    ComparisonEntry,
    VerificationResult,
    VerificationSample,
)

UNOBSERVED_NOTE = (
    "Not observed in this run: this does not mean fixed. Only gazua verify closes a finding."
)
TOOLS_NOTE = (
    "Tools mode repeats direct calls: it checks the control in the tested context, not how a "
    "model resists."
)
SEPARATE_RATES = "Each scenario has its own rate and bound; they are not added into one sample."
REASON_TEXT = {
    "verification_incomplete": "fewer than 20 conclusive repetitions in a scenario",
    "verification_low_fidelity": "low fidelity evidence",
    "operational_error": "an operational error",
    "cleanup_failed": "the final reset failed",
    "interrupted": "the run was interrupted",
    "not_applicable": "a scenario was not applicable",
}


def bound_text(value: float | None) -> str:
    """``up to ~14%`` for the 95% upper bound of 0/20; ``no bound`` when there is none."""
    if value is None:
        return "no bound"
    return f"up to ~{round(value * 100)}%"


def sample_text(sample: VerificationSample) -> str:
    """``0/20, up to ~14%``: successes over evaluated repetitions and the native bound."""
    text = f"{sample.successes}/{sample.evaluated}, {bound_text(sample.upper_bound)}"
    if sample.evaluated != sample.planned:
        text += f" ({sample.planned} planned)"
    return text


def entry_text(item: ComparisonEntry) -> str:
    previous = item.baseline_status or "not in baseline"
    text = f"{item.finding_id}: {item.status} (baseline: {previous})"
    if item.regression:
        text += ", closed before and found again"
    if item.effective_gated:
        text += ", gated"
    elif item.native_gated and item.observed:
        text += ", gated natively, accepted in the baseline"
    return text


def comparison_lines(comparison: BaselineComparison) -> list[str]:
    """The count line, each new finding, then the history this run did not confirm."""
    lines = [f"Baseline (revision {comparison.baseline_revision}): {summary_text(comparison)}."]
    lines.extend(
        f"  New: {entry_text(item)}." for item in comparison.observed if item.status == "new"
    )
    unobserved = comparison.unobserved
    if unobserved:
        open_count = sum(item.status == "open" for item in unobserved)
        closed_count = len(unobserved) - open_count
        lines.append(
            f"  {len(unobserved)} baseline entries not observed in this run "
            f"({open_count} open, {closed_count} closed). {UNOBSERVED_NOTE}"
        )
    return lines


def reasons_text(result: VerificationResult) -> str:
    return ", ".join(REASON_TEXT.get(item, item.replace("_", " ")) for item in result.reasons)


def verification_lines(
    result: VerificationResult, mode: str, *, persisted: bool | None = None
) -> list[str]:
    """Each scenario's rate, then the decision.

    ``persisted`` is None in a report: it states what the evidence allowed then. The CLI passes
    True only after the baseline was replaced, and only then names the new state.
    """
    lines = [
        f"Verification of {result.finding_id} ({len(result.samples)} scenarios, 20 repetitions "
        "each):"
    ]
    for sample in result.samples:
        lines.append(f"  Scenario {sample.attack_key} ({sample.language}): {sample_text(sample)}.")
    if len(result.samples) > 1:
        lines.append(f"  {SEPARATE_RATES}")
    if mode == "tools":
        lines.append(f"  {TOOLS_NOTE}")
    lines.append(decision_text(result, persisted))
    return lines


def decision_text(result: VerificationResult, persisted: bool | None) -> str:
    worst = _headline(result)
    if result.outcome == "interrupted":
        return f"Interrupted: the finding stays {result.previous_status}; nothing was changed."
    if persisted is None:
        if result.outcome == "verified":
            return f"{_counts(result)}; closure eligible at verification time."
        if result.proposed_status == "open":
            note = f" Not complete: {reasons_text(result)}." if result.reasons else ""
            return f"{worst}; the finding stays open at verification time.{note}"
        return (
            f"{worst}; not verified ({reasons_text(result)}), so the finding keeps its state "
            f"({result.previous_status})."
        )
    if not persisted:
        return (
            f"{worst}; the baseline could not be updated, so the finding keeps its state "
            f"({result.previous_status})."
        )
    if result.proposed_status is not None:
        note = f" Not complete: {reasons_text(result)}." if result.outcome == "incomplete" else ""
        return f"{worst}: {result.proposed_status}.{note}"
    return (
        f"{worst}: not verified ({reasons_text(result)}). The finding stays "
        f"{result.previous_status}; this verification did not confirm it."
    )


def _counts(result: VerificationResult) -> str:
    return ", ".join(f"{item.successes}/{item.evaluated}" for item in result.samples)


def _headline(result: VerificationResult) -> str:
    """The sample that decides: a success if there is one, else the first scenario."""
    if not result.samples:
        return "No scenario was sampled"
    chosen = next((item for item in result.samples if item.successes), result.samples[0])
    return sample_text(chosen)


@dataclass(frozen=True, slots=True)
class ComparisonView:
    """What the reports show of a comparison: the count line and one row per entry."""

    summary: str
    observed: tuple[tuple[str, str, str, str], ...]
    unobserved: tuple[tuple[str, str], ...]
    note: str


def comparison_view(comparison: BaselineComparison | None) -> ComparisonView | None:
    if comparison is None:
        return None
    observed = tuple(
        (
            item.finding_id,
            item.baseline_status or "none",
            item.status + (" (regression)" if item.regression else ""),
            "yes" if item.effective_gated else ("accepted" if item.native_gated else "no"),
        )
        for item in comparison.observed
    )
    unobserved = tuple((item.finding_id, item.status) for item in comparison.unobserved)
    summary = f"Revision {comparison.baseline_revision}: {summary_text(comparison)}."
    return ComparisonView(summary, observed, unobserved, UNOBSERVED_NOTE)


@dataclass(frozen=True, slots=True)
class VerificationView:
    """What the reports show of a verification: one row per scenario and the decision."""

    finding_id: str
    rows: tuple[tuple[str, str, str, str], ...]
    decision: str
    notes: tuple[str, ...]


def verification_view(result: VerificationResult | None, mode: str) -> VerificationView | None:
    if result is None:
        return None
    rows = tuple(
        (item.attack_key, item.language, sample_text(item), item.coverage)
        for item in result.samples
    )
    notes: list[str] = []
    if len(result.samples) > 1:
        notes.append(SEPARATE_RATES)
    if mode == "tools":
        notes.append(TOOLS_NOTE)
    return VerificationView(result.finding_id, rows, decision_text(result, None), tuple(notes))


__all__ = [
    "ComparisonView",
    "VerificationView",
    "bound_text",
    "comparison_lines",
    "comparison_view",
    "decision_text",
    "sample_text",
    "verification_lines",
    "verification_view",
]
