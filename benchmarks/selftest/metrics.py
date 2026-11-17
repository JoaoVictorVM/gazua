"""Rates with their denominators, taken only from the cells of one result.

A zero denominator has no rate: it is shown as "not applicable", never as 0% or 100%. Rows of
different implementations are never merged into one number that would hide a weaker one.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from fractions import Fraction
from typing import Final

from .models import CellResult, Counts

NOT_APPLICABLE: Final = "not applicable"


@dataclass(frozen=True, slots=True)
class Rate:
    numerator: int
    denominator: int

    @property
    def value(self) -> Fraction | None:
        return None if self.denominator == 0 else Fraction(self.numerator, self.denominator)

    def text(self) -> str:
        value = self.value
        if value is None:
            return NOT_APPLICABLE
        percent = (value * 1000).__round__() / 10
        return f"{percent:.1f}% ({self.numerator}/{self.denominator})"


@dataclass(frozen=True, slots=True)
class Row:
    """One line of the published table: an implementation, a mode and a language."""

    framework: str
    mode: str
    language: str
    detection: Rate
    false_alarms: Rate
    unexpected_findings: int
    coverage: Rate
    pending: int
    errors: int


def _rows_key(cell: CellResult) -> tuple[str, str, str]:
    return (cell.framework or "-", cell.mode or "-", cell.language or "-")


def rows(cells: Iterable[CellResult]) -> list[Row]:
    targets = [cell for cell in cells if cell.kind == "target" and cell.mold_id is not None]
    found: list[Row] = []
    for key in sorted({_rows_key(cell) for cell in targets}):
        group = [cell for cell in targets if _rows_key(cell) == key]
        positive = [cell for cell in group if cell.positive]
        negative = [cell for cell in group if cell.negative]
        concluded = [cell for cell in group if cell.outcome in ("passed", "failed")]
        expected = {
            (cell.case_id, item.sort_key()) for cell in group for item in cell.expected_findings
        }
        found.append(
            Row(
                framework=key[0],
                mode=key[1],
                language=key[2],
                detection=Rate(
                    sum(1 for cell in positive if cell.outcome == "passed"), len(positive)
                ),
                false_alarms=Rate(
                    sum(
                        1
                        for cell in negative
                        if cell.outcome in ("passed", "failed") and cell.observed_findings
                    ),
                    len(negative),
                ),
                unexpected_findings=sum(
                    1
                    for cell in group
                    for item in cell.observed_findings
                    if (cell.case_id, item.sort_key()) not in expected
                ),
                coverage=Rate(len(concluded), len(group)),
                pending=sum(1 for cell in group if cell.outcome == "pending"),
                errors=sum(1 for cell in group if cell.outcome == "error"),
            )
        )
    return found


def controls(counts: Counts) -> Rate:
    return Rate(counts.controls_detected, counts.controls_expected)


def detection(counts: Counts) -> Rate:
    return Rate(counts.positive_detected, counts.positive_expected)


def false_alarms(counts: Counts) -> Rate:
    return Rate(counts.false_alarm_cells, counts.negative_expected)


__all__ = ["NOT_APPLICABLE", "Rate", "Row", "controls", "detection", "false_alarms", "rows"]
