"""The first run document format, read as it was written and adapted in memory.

A schema 1 document is validated against its own contract first. The adaptation adds only what
the document already implies: each scenario's reference from its attack key and the run's
language, and no baseline comparison or verification, since none existed. It then follows the
schema 2 adaptation, which adds the frozen fallback guide. Files are never rewritten; new runs
are written in the current format.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from gazua.baseline.models import scenario_digest
from gazua.catalog.models import Damage, Entry, Technique
from gazua.config.models import SCHEMA_DIALECT
from gazua.modes.agent_models import LegitimateUse
from gazua.reports.models import (
    ExitCode,
    Finding,
    ProofSnapshot,
    RedactionMode,
    ReportDiagnostic,
    Reproduction,
    RunMetadata,
    SyntheticData,
    check_document,
)
from gazua.reports.models import RunDocument as CurrentRunDocument
from gazua.runtime.run_models import GazuaId, NonEmptyText, RunSummary
from gazua.verdicts.models import AttackKey, VerdictSummary

RUN_V1_SCHEMA_FILE: Final = "run-v1.schema.json"
_SCHEMA_BASE: Final = "https://raw.githubusercontent.com/JoaoVictorVM/gazua/main/src/gazua/schemas/"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Scenario(_Strict):
    """One attack unit as the report shows it. Its key finds exactly one attack result."""

    attack_key: AttackKey
    mold_id: NonEmptyText
    tool_name: str | None
    record_index: Annotated[int, Field(ge=0)] | None
    canary_index: Annotated[int, Field(ge=0)] | None
    entry: Entry
    technique: Technique
    attack: NonEmptyText
    payload: JsonValue
    reproduction: Reproduction


class RunDocument(_Strict):
    """Everything the reports need, checked against the native verdicts."""

    model_config = ConfigDict(title="Gazua run document")

    schema_version: Literal[1]
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

    @model_validator(mode="after")
    def _consistent(self) -> RunDocument:
        problems = check_document(self)
        if problems:
            raise ValueError("; ".join(problems))
        return self


def adapt(document: RunDocument) -> CurrentRunDocument:
    """The schema 1 document in the current contract, with no comparison or verification."""
    from gazua.reports.legacy_v2 import adapt_data

    language = document.metadata.language
    data: dict[str, Any] = document.model_dump(mode="json")
    data["schema_version"] = 2
    for scenario in data["scenarios"]:
        scenario["baseline_reference"] = {
            "scenario_digest": scenario_digest(scenario["attack_key"]),
            "language": language,
        }
    data["baseline"] = None
    data["verification"] = None
    return adapt_data(data)


def build_run_v1_json_schema() -> dict[str, Any]:
    schema = RunDocument.model_json_schema(mode="validation")
    return {"$schema": SCHEMA_DIALECT, "$id": _SCHEMA_BASE + RUN_V1_SCHEMA_FILE, **schema}


def render_run_v1_json_schema() -> str:
    return json.dumps(build_run_v1_json_schema(), indent=2) + "\n"


def packaged_run_v1_json_schema() -> str:
    from importlib.resources import files

    return files("gazua").joinpath(f"schemas/{RUN_V1_SCHEMA_FILE}").read_text(encoding="utf-8")


__all__ = [
    "RUN_V1_SCHEMA_FILE",
    "RunDocument",
    "Scenario",
    "adapt",
    "build_run_v1_json_schema",
    "packaged_run_v1_json_schema",
    "render_run_v1_json_schema",
]
