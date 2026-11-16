"""The second run document format, read as it was written and adapted in memory.

A schema 2 document is validated against its own contract first, with its baseline comparison
and verification. The adaptation adds only the frozen fallback guide, marked as added on
reading, and keeps every id, scenario reference, comparison and verification as they were.
Files are never rewritten; new runs are written in the current format.
"""

from __future__ import annotations

import json
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, model_validator

from gazua.baseline.models import BaselineComparison, VerificationResult
from gazua.catalog.models import Damage
from gazua.config.models import SCHEMA_DIALECT
from gazua.modes.agent_models import LegitimateUse
from gazua.reports.legacy_guides import fallback_guide
from gazua.reports.models import (
    RUN_SCHEMA_VERSION,
    ExitCode,
    Finding,
    ProofSnapshot,
    RedactionMode,
    ReportDiagnostic,
    RunMetadata,
    Scenario,
    SyntheticData,
    check_document,
    snapshot_problems,
)
from gazua.reports.models import RunDocument as CurrentRunDocument
from gazua.runtime.run_models import GazuaId, NonEmptyText, RunSummary
from gazua.verdicts.models import VerdictSummary

RUN_V2_SCHEMA_FILE: Final = "run-v2.schema.json"
_SCHEMA_BASE: Final = "https://raw.githubusercontent.com/JoaoVictorVM/gazua/main/src/gazua/schemas/"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class RunDocument(_Strict):
    """Everything the reports need, checked against the native verdicts."""

    model_config = ConfigDict(title="Gazua run document")

    schema_version: Literal[2]
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

    @model_validator(mode="after")
    def _consistent(self) -> RunDocument:
        problems = [*check_document(self), *snapshot_problems(self)]
        if problems:
            raise ValueError("; ".join(problems))
        return self


def adapt_data(data: dict[str, Any]) -> CurrentRunDocument:
    """A schema 2 document's JSON data in the current contract, with the fallback guide."""
    current = dict(data)
    current["schema_version"] = RUN_SCHEMA_VERSION
    current["guide"] = fallback_guide(data["metadata"]["language"]).model_dump(mode="json")
    return CurrentRunDocument.model_validate_json(json.dumps(current))


def adapt(document: RunDocument) -> CurrentRunDocument:
    return adapt_data(document.model_dump(mode="json"))


def build_run_v2_json_schema() -> dict[str, Any]:
    schema = RunDocument.model_json_schema(mode="validation")
    return {"$schema": SCHEMA_DIALECT, "$id": _SCHEMA_BASE + RUN_V2_SCHEMA_FILE, **schema}


def render_run_v2_json_schema() -> str:
    return json.dumps(build_run_v2_json_schema(), indent=2) + "\n"


def packaged_run_v2_json_schema() -> str:
    from importlib.resources import files

    return files("gazua").joinpath(f"schemas/{RUN_V2_SCHEMA_FILE}").read_text(encoding="utf-8")


__all__ = [
    "RUN_V2_SCHEMA_FILE",
    "RunDocument",
    "adapt",
    "adapt_data",
    "build_run_v2_json_schema",
    "packaged_run_v2_json_schema",
    "render_run_v2_json_schema",
]
