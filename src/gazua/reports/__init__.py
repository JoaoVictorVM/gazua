"""Findings and evidence reports: the persisted run document and its presentations.

Importing this package loads only contracts. It never imports a target, reads a configuration
or touches the filesystem; rendering, storage and capture live in their own modules.
"""

from gazua.reports.builder import build_run_document, finding_id
from gazua.reports.fixes import FIXES, fix_anchor, fix_text
from gazua.reports.models import (
    RUN_SCHEMA_FILE,
    Finding,
    ProofSnapshot,
    ReportDiagnostic,
    Reproduction,
    RunDocument,
    RunMetadata,
    Scenario,
    SyntheticData,
)

__all__ = [
    "FIXES",
    "RUN_SCHEMA_FILE",
    "Finding",
    "ProofSnapshot",
    "ReportDiagnostic",
    "Reproduction",
    "RunDocument",
    "RunMetadata",
    "Scenario",
    "SyntheticData",
    "build_run_document",
    "finding_id",
    "fix_anchor",
    "fix_text",
]
