"""The persisted run document: findings, scenarios, proof snapshots and run metadata.

The document is self-contained. Reports are rebuilt from it alone, without importing the
target, reading the configuration or opening the evidence files it mentions. Verdicts stay the
only source of state, severity, counts, rates, bounds and gates; the document carries them as
they are and checks that its own collections agree with them.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Annotated, Any, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from gazua.catalog.models import DAMAGES, Damage, Entry, Language, Mode, Technique
from gazua.config.models import SCHEMA_DIALECT, Severity
from gazua.runtime.run_models import GazuaId, NonEmptyText, RunSummary, UtcTimestamp
from gazua.verdicts.models import AttackKey, ProofCondition, VerdictSummary

RUN_SCHEMA_FILE = "run-v1.schema.json"
RUN_SCHEMA_VERSION = 1
PRESENTATION_VERSION = 1
_SCHEMA_BASE = "https://raw.githubusercontent.com/JoaoVictorVM/gazua/main/src/gazua/schemas/"
SEVERITY_ORDER: dict[Severity, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3}

RedactionMode: TypeAlias = Literal["masked", "none"]
SnapshotSource: TypeAlias = Literal[
    "call", "tool_return", "output", "receiver", "sink", "memory", "operational"
]
DiagnosticLevel: TypeAlias = Literal["warning", "error"]
ExitCode: TypeAlias = Literal[0, 1, 2]
Code = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$")]
FindingId = Annotated[str, Field(pattern=r"^finding-[0-9a-f]{64}$")]
ProofId = Annotated[str, Field(pattern=r"^proof-[0-9]{6,}$")]
RelativePath = Annotated[
    str, Field(pattern=r"^(\.|[A-Za-z0-9_][A-Za-z0-9._-]*(/[A-Za-z0-9_][A-Za-z0-9._-]*)*)$")
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ReportDiagnostic(_Strict):
    """Something the report found while treating data. It never quotes the value."""

    code: Code
    field: str | None = None
    level: DiagnosticLevel = "warning"


class Reproduction(_Strict):
    """An argument list to run in ``cwd``, relative to the project root. Never run by Gazua.

    An unavailable command keeps its reason and is not offered for copying.
    """

    argv: list[str]
    cwd: RelativePath = "."
    available: bool
    reason: Code | None = None

    @model_validator(mode="after")
    def _reasoned(self) -> Reproduction:
        if self.available == (self.reason is not None):
            raise ValueError("An unavailable command needs a reason; an available one has none.")
        if self.available and not self.argv:
            raise ValueError("An available command has arguments.")
        return self


class RunMetadata(_Strict):
    """When and how the run happened. Nothing absent is invented."""

    created_at: UtcTimestamp
    gazua_version: str | None
    target_version: str | None
    model: str | None
    mode: Mode
    target_ref: NonEmptyText
    language: Language
    presentation_version: Annotated[int, Field(ge=1)]


class SyntheticIdentity(_Strict):
    role: Literal["attacker", "victim"]
    id: NonEmptyText


class SyntheticRecord(_Strict):
    owner: Literal["attacker", "victim"]
    tool: NonEmptyText
    id_arg: NonEmptyText
    id: NonEmptyText | int


class SyntheticData(_Strict):
    """Declared test data that stays visible: fixture identities, records and canaries."""

    identities: list[SyntheticIdentity] = Field(default_factory=list[SyntheticIdentity])
    records: list[SyntheticRecord] = Field(default_factory=list[SyntheticRecord])
    canaries: list[NonEmptyText] = Field(default_factory=list[str])


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


class Finding(_Strict):
    """Proven scenarios of one target, mode, mold and tool, under one stable id."""

    id: FindingId
    mode: Mode
    mold_id: NonEmptyText
    tool_name: str | None
    damage: Damage
    severity: Severity
    gated: bool
    scenarios: Annotated[list[AttackKey], Field(min_length=1)]
    attack: NonEmptyText
    proof_ids: list[ProofId]
    conditions: list[ProofCondition]
    reproduction: Reproduction
    fix_ref: Damage
    fix: NonEmptyText


class ProofSnapshot(_Strict):
    """A treated excerpt of the evidence behind one native proof.

    ``attack_key`` and ``proof_index`` locate the proof in the verdicts. ``content`` is null
    when no excerpt could be kept, and ``omission_reason`` then says why.
    """

    id: ProofId
    attack_key: AttackKey
    proof_index: Annotated[int, Field(ge=0)]
    execution_id: GazuaId
    source: SnapshotSource
    locator: dict[str, JsonValue]
    content: JsonValue
    truncated: bool
    omission_reason: Code | None


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

    @model_validator(mode="after")
    def _consistent(self) -> RunDocument:
        problems = check_document(self)
        if problems:
            raise ValueError("; ".join(problems))
        return self

    def scenario(self, attack_key: str) -> Scenario:
        return next(item for item in self.scenarios if item.attack_key == attack_key)


def highest_severity(values: Iterable[Severity]) -> Severity:
    return min(values, key=lambda item: SEVERITY_ORDER[item])


def _duplicates(values: list[str]) -> bool:
    return len(set(values)) != len(values)


def check_document(document: RunDocument) -> list[str]:
    """Every cross-reference rule the document must keep; empty when it is consistent."""
    problems: list[str] = []
    if document.engine.run_id != document.run_id or document.verdicts.run_id != document.run_id:
        problems.append("The run id differs between the document and its summaries.")
    results = {item.attack_key: item for item in document.verdicts.results}
    keys = [item.attack_key for item in document.scenarios]
    if _duplicates(keys):
        problems.append("Each attack key has one scenario.")
    if set(keys) != set(results) or len(keys) != len(results):
        problems.append("Scenarios and verdict results differ.")
    finding_ids = [item.id for item in document.findings]
    if _duplicates(finding_ids):
        problems.append("Each finding id appears once.")
    proof_ids = [item.id for item in document.proofs]
    if _duplicates(proof_ids):
        problems.append("Each proof id appears once.")
    if set(document.fixes) != set(DAMAGES):
        problems.append("Every damage has its fix.")
    snapshots = {item.id: item for item in document.proofs}
    for snapshot in document.proofs:
        result = results.get(snapshot.attack_key)
        if result is None or snapshot.proof_index >= len(result.proof):
            problems.append("A proof snapshot points to a proof that does not exist.")
        elif result.proof[snapshot.proof_index].execution_id != snapshot.execution_id:
            problems.append("A proof snapshot names another execution.")
    grouped: set[str] = set()
    scenarios = {item.attack_key: item for item in document.scenarios}
    for finding in document.findings:
        members = [results.get(key) for key in finding.scenarios]
        if any(item is None or item.state != "finding" or not item.proof for item in members):
            problems.append("A finding groups only proven scenarios.")
            continue
        proven = [item for item in members if item is not None]
        if grouped & set(finding.scenarios):
            problems.append("A scenario belongs to one finding.")
        grouped |= set(finding.scenarios)
        if any(
            item.mold_id != finding.mold_id
            or item.mode != finding.mode
            or item.damage != finding.damage
            or scenarios[item.attack_key].tool_name != finding.tool_name
            for item in proven
        ):
            problems.append("A finding groups scenarios of one mold, mode and tool.")
        if finding.gated != any(item.gated for item in proven):
            problems.append("A finding's gate is the OR of its scenarios.")
        if finding.severity != highest_severity(item.severity for item in proven):
            problems.append("A finding's severity is the highest of its scenarios.")
        if finding.fix_ref != finding.damage:
            problems.append("A finding's fix reference is its damage.")
        if not finding.proof_ids or any(
            snapshots.get(item) is None or snapshots[item].attack_key not in finding.scenarios
            for item in finding.proof_ids
        ):
            problems.append("A finding's proofs belong to its scenarios.")
    proven_keys = {key for key, item in results.items() if item.state == "finding"}
    if proven_keys != grouped:
        problems.append("Every proven scenario belongs to exactly one finding.")
    return problems


def build_run_json_schema() -> dict[str, Any]:
    schema = RunDocument.model_json_schema(mode="validation")
    return {"$schema": SCHEMA_DIALECT, "$id": _SCHEMA_BASE + RUN_SCHEMA_FILE, **schema}


def render_run_json_schema() -> str:
    return json.dumps(build_run_json_schema(), indent=2) + "\n"


def packaged_run_json_schema() -> str:
    """The run schema distributed with this package, read without network access."""
    from importlib.resources import files

    return files("gazua").joinpath(f"schemas/{RUN_SCHEMA_FILE}").read_text(encoding="utf-8")
