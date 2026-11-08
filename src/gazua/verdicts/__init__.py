"""Verdict engine: turns recorded effects into one state per attack, decided by code only.

Modes, reports, verification and adapters consume these results instead of interpreting
evidence themselves. Nothing here runs at ``import gazua``.
"""

from gazua.verdicts.models import (
    VERDICT_STATES,
    AttackContext,
    AttackResult,
    AttemptVerdict,
    Capabilities,
    Impediment,
    Proof,
    Reason,
    RequestSlot,
    ResultPaths,
    StateCounts,
    VerdictState,
    VerdictSummary,
)

__all__ = [
    "VERDICT_STATES",
    "AttackContext",
    "AttackResult",
    "AttemptVerdict",
    "Capabilities",
    "Impediment",
    "Proof",
    "Reason",
    "RequestSlot",
    "ResultPaths",
    "StateCounts",
    "VerdictState",
    "VerdictSummary",
]
