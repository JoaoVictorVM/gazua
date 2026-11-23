"""The fourth run document format, read as it was written and adapted in memory.

A schema 4 document is validated against its own contract first. That format reached Python
and MCP targets only, so the adaptation records no HTTP provenance and keeps every id,
scenario, comparison, verification, guide and MCP summary as they were. Files are never
rewritten; new runs are written in the current format.
"""

from __future__ import annotations

import json
from typing import Any, Final, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, model_validator

from gazua.baseline.models import BaselineComparison, VerificationResult
from gazua.catalog.models import Damage
from gazua.config.models import SCHEMA_DIALECT
from gazua.modes.agent_models import LegitimateUse
from gazua.reports.guide_models import FixGuide
from gazua.reports.models import (
    RUN_SCHEMA_VERSION,
    ExitCode,
    Finding,
    McpProvenance,
    ProofSnapshot,
    RedactionMode,
    ReportDiagnostic,
    RunMetadata,
    Scenario,
    SyntheticData,
    check_document,
    guide_problems,
    mcp_problems,
    snapshot_problems,
)
from gazua.reports.models import RunDocument as CurrentRunDocument
from gazua.runtime.run_models import GazuaId, NonEmptyText, RunSummary
from gazua.verdicts.models import VerdictSummary

RUN_V4_SCHEMA_FILE: Final = "run-v4.schema.json"
_SCHEMA_BASE: Final = "https://raw.githubusercontent.com/JoaoVictorVM/gazua/main/src/gazua/schemas/"
TargetAdapterV4: TypeAlias = Literal["python", "mcp_stdio"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class RunDocument(_Strict):
    """Everything the reports need, checked against the native verdicts."""

    model_config = ConfigDict(title="Gazua run document")

    schema_version: Literal[4]
    run_id: GazuaId
    metadata: RunMetadata
    redaction: RedactionMode
    synthetic_data: SyntheticData
    engine: RunSummary
    verdicts: VerdictSummary
    scenarios: list[Scenario]
    findings: list[Finding]
    proofs: list[ProofSnapshot]
    fixes: dict[Damage, NonEmptyText]
    diagnostics: list[ReportDiagnostic]
    report_exit_code: ExitCode
    legitimate_use: LegitimateUse | None = None
    baseline: BaselineComparison | None
    verification: VerificationResult | None
    # The guide as the run captured it; reports never replace it with the installed catalog.
    guide: FixGuide
    # How the target was reached. Documents read from older formats were Python targets.
    target_adapter: TargetAdapterV4
    mcp: McpProvenance | None

    @model_validator(mode="after")
    def _consistent(self) -> RunDocument:
        problems = [
            *check_document(self),
            *snapshot_problems(self),
            *guide_problems(self),
            *mcp_problems(self),
        ]
        if problems:
            raise ValueError("; ".join(problems))
        return self


def adapt_data(data: dict[str, Any]) -> CurrentRunDocument:
    """A schema 4 document's JSON data in the current contract, with no HTTP provenance."""
    current = dict(data)
    current["schema_version"] = RUN_SCHEMA_VERSION
    current["http"] = None
    return CurrentRunDocument.model_validate_json(json.dumps(current))


def adapt(document: RunDocument) -> CurrentRunDocument:
    return adapt_data(document.model_dump(mode="json"))


def build_run_v4_json_schema() -> dict[str, Any]:
    schema = RunDocument.model_json_schema(mode="validation")
    return {"$schema": SCHEMA_DIALECT, "$id": _SCHEMA_BASE + RUN_V4_SCHEMA_FILE, **schema}


def render_run_v4_json_schema() -> str:
    return json.dumps(build_run_v4_json_schema(), indent=2) + "\n"


def packaged_run_v4_json_schema() -> str:
    from importlib.resources import files

    return files("gazua").joinpath(f"schemas/{RUN_V4_SCHEMA_FILE}").read_text(encoding="utf-8")


__all__ = [
    "RUN_V4_SCHEMA_FILE",
    "RunDocument",
    "adapt",
    "adapt_data",
    "build_run_v4_json_schema",
    "packaged_run_v4_json_schema",
    "render_run_v4_json_schema",
]
