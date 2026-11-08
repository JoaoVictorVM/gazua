"""Controlled wording for verdicts and the table by damage. Reports render from here.

Every sentence comes from a fixed template. Nothing the target returned is interpolated, and the
vocabulary has no approval words: a resisted attack is reported for this version and this model,
never as a property of the agent.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from gazua.catalog.models import DAMAGES, Damage, Mode
from gazua.verdicts.models import (
    VERDICT_STATES,
    AttackResult,
    Reason,
    StateCounts,
    VerdictState,
    VerdictSummary,
)

FORBIDDEN_TERMS = ("approved", "secure")
NOT_REPORTED = "not reported"
STATE_LABELS: dict[VerdictState, str] = {
    "finding": "finding",
    "conditional_risk": "conditional risk, not verified",
    "resisted": "resisted",
    "not_tested": "not tested",
    "not_applicable": "not applicable",
}
DAMAGE_LABELS: dict[Damage, str] = {
    "prompt_only_permission": "Permission only in the prompt",
    "secret_in_context": "Secret in the context",
    "idor_via_agent": "Records of another user",
    "unhandled_output": "Unhandled output",
    "unlocked_memory": "Unlocked memory",
    "unchecked_spending": "Unchecked spending",
}


def requirement_label(requirement: str) -> str:
    """``tool.owner_arg`` reads as ``owner_arg``, the field the user declares."""
    return requirement.removeprefix("tool.")


def reason_text(reason: Reason) -> str:
    if reason.missing:
        return "missing " + ", ".join(requirement_label(item) for item in reason.missing)
    return reason.code.replace("_", " ")


def state_text(result: AttackResult) -> str:
    """The state with its reasons, for example ``not tested, missing owner_arg``."""
    label = STATE_LABELS[result.state]
    if result.state in ("not_tested", "conditional_risk", "not_applicable") and result.reasons:
        details = "; ".join(reason_text(item) for item in result.reasons)
        return (
            f"{label} ({details})" if result.state == "conditional_risk" else f"{label}, {details}"
        )
    return label


def percent(value: float) -> int:
    return round(value * 100)


def rate_text(result: AttackResult) -> str:
    """``1/5, up to ~66%``. The bound covers only the repetitions that were evaluated."""
    if result.evaluated == 0:
        return "no evaluated repetitions"
    text = f"{result.successes}/{result.evaluated}"
    if result.upper_bound is None:
        text += ", upper bound unavailable"
    else:
        text += f", up to ~{percent(result.upper_bound)}%"
    if result.coverage == "partial":
        text += f" (observed sample; {result.unknown} of {result.planned} not evaluated)"
    return text


def resisted_text(
    count: int, mode: Mode, *, version: str | None = None, model: str | None = None
) -> str:
    """How resistance is worded: for this version and this model, never in general."""
    noun = "attack" if count == 1 else "attacks"
    shown_version = version or NOT_REPORTED
    if mode == "tools":
        return (
            f"Resisted {count} {noun} in tools mode, on this version "
            f"(version: {shown_version}); no model was involved."
        )
    return (
        f"Resisted {count} {noun}, on this version and with this model "
        f"(version: {shown_version}, model: {model or NOT_REPORTED})."
    )


@dataclass(frozen=True, slots=True)
class DamageRow:
    """One line of the table by damage."""

    damage: Damage
    label: str
    counts: StateCounts
    gated: int
    not_tested: tuple[str, ...]


def damage_table(summary: VerdictSummary) -> list[DamageRow]:
    rows: list[DamageRow] = []
    for damage in DAMAGES:
        results = [item for item in summary.results if item.damage == damage]
        if not results:
            continue
        reasons = tuple(
            f"{item.attack_key}: {state_text(item)}"
            for item in results
            if item.state == "not_tested"
        )
        rows.append(
            DamageRow(
                damage=damage,
                label=DAMAGE_LABELS[damage],
                counts=summary.counts_by_damage[damage],
                gated=sum(item.gated for item in results),
                not_tested=reasons,
            )
        )
    return rows


def _row(cells: Sequence[str]) -> str:
    return "| " + " | ".join(cells) + " |"


def summary_lines(
    summary: VerdictSummary, *, version: str | None = None, model: str | None = None
) -> list[str]:
    """Plain lines with the table by damage, each attack and the gate. Not a report format."""
    header = ["Damage", *(STATE_LABELS[state] for state in VERDICT_STATES), "gated"]
    lines = [_row(header), _row(["---"] * len(header))]
    for row in damage_table(summary):
        counts = [str(getattr(row.counts, state)) for state in VERDICT_STATES]
        lines.append(_row([row.label, *counts, str(row.gated)]))
    for row in damage_table(summary):
        lines.extend(f"- {item}" for item in row.not_tested)
    for result in summary.results:
        lines.append(
            f"{result.attack_key} [{result.severity}, {result.mode}]: "
            f"{state_text(result)}; {rate_text(result)}"
        )
    for mode in ("agent", "tools"):
        resisted = [
            item for item in summary.results if item.mode == mode and item.state == "resisted"
        ]
        if resisted:
            lines.append(resisted_text(len(resisted), mode, version=version, model=model))
    gated = sum(result.gated for result in summary.results)
    lines.append(
        f"Gate: {gated} finding{'' if gated == 1 else 's'} at a gated severity."
        if gated
        else "Gate: no finding at a gated severity."
    )
    if summary.operational_errors:
        lines.append("Operational errors: " + ", ".join(summary.operational_errors))
    return lines
