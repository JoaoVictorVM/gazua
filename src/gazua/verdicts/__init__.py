"""Verdict engine: turns recorded effects into one state per attack, decided by code only.

Modes, reports, verification and adapters consume these results instead of interpreting
evidence themselves. Nothing here runs at ``import gazua``.
"""

from gazua.verdicts.engine import VerdictCollector, VerdictContractError, evaluate_attempt
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
from gazua.verdicts.presentation import rate_text, resisted_text, state_text, summary_lines
from gazua.verdicts.statistics import upper_bound

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
    "VerdictCollector",
    "VerdictContractError",
    "VerdictState",
    "VerdictSummary",
    "evaluate_attempt",
    "rate_text",
    "resisted_text",
    "state_text",
    "summary_lines",
    "upper_bound",
]
