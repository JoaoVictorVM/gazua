"""Baseline of accepted findings, comparison of runs against it and verification of fixes.

Only the contracts are imported here; operations live in their modules and are imported where
they are used, so reading a baseline never pulls in the run engine or the target.
"""

from gazua.baseline.models import (
    BASELINE_FILE,
    BASELINE_SCHEMA_VERSION,
    VERIFY_REPETITIONS,
    BaselineDocument,
    BaselineEntry,
    ScenarioReference,
    VerificationReceipt,
)

__all__ = [
    "BASELINE_FILE",
    "BASELINE_SCHEMA_VERSION",
    "VERIFY_REPETITIONS",
    "BaselineDocument",
    "BaselineEntry",
    "ScenarioReference",
    "VerificationReceipt",
]
