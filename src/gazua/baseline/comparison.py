"""Compares a run's findings with a baseline. Pure: no I/O, no change to native results.

A finding is known when its entry is open, new when there is no entry, and new again with
``regression`` when its entry was closed. Only new findings keep their native gate. Entries
the run did not observe are reported apart and never look fixed. Operational errors keep exit
code 2 whatever the comparison says.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal, Protocol

from gazua.baseline.models import (
    BaselineComparison,
    BaselineDocument,
    ComparedStatus,
    ComparisonEntry,
)


class ObservedFinding(Protocol):
    """What the comparison reads of a finding: its id and its native gate."""

    @property
    def id(self) -> str: ...

    @property
    def gated(self) -> bool: ...


def compare(
    findings: Sequence[ObservedFinding], baseline: BaselineDocument, digest: str
) -> BaselineComparison:
    """The comparison of the run's findings, in their order, then the unobserved entries."""
    entries: list[ComparisonEntry] = []
    seen: set[str] = set()
    for finding in findings:
        if finding.id in seen:
            continue
        seen.add(finding.id)
        persisted = baseline.entry(finding.id)
        previous = None if persisted is None else persisted.status
        status: ComparedStatus = "open" if previous == "open" else "new"
        entries.append(
            ComparisonEntry(
                finding_id=finding.id,
                baseline_status=previous,
                status=status,
                observed=True,
                regression=previous == "closed",
                native_gated=finding.gated,
                effective_gated=status == "new" and finding.gated,
            )
        )
    entries.extend(
        ComparisonEntry(
            finding_id=item.id,
            baseline_status=item.status,
            status=item.status,
            observed=False,
            regression=False,
            native_gated=False,
            effective_gated=False,
        )
        for item in baseline.entries
        if item.id not in seen
    )
    observed = entries[: len(seen)]
    return BaselineComparison(
        schema_version=1,
        baseline_revision=baseline.revision,
        baseline_digest=digest,
        observed_known=sum(item.status == "open" for item in observed),
        observed_new=sum(item.status == "new" for item in observed),
        has_new_gated_findings=any(item.effective_gated for item in observed),
        entries=entries,
    )


def effective_exit(native: Literal[0, 1, 2], comparison: BaselineComparison) -> Literal[0, 1, 2]:
    """2 stays 2; otherwise 1 only for a new gated finding. Known findings never fail."""
    if native == 2:
        return 2
    return 1 if comparison.has_new_gated_findings else 0


def summary_text(comparison: BaselineComparison) -> str:
    """The one-line count a run shows, such as ``2 known findings, 0 new``."""
    known = comparison.observed_known
    noun = "finding" if known == 1 else "findings"
    text = f"{known} known {noun}, {comparison.observed_new} new"
    regressions = sum(item.regression for item in comparison.observed)
    if regressions:
        text += f" ({regressions} closed before and found again)"
    return text


__all__ = ["ObservedFinding", "compare", "effective_exit", "summary_text"]
