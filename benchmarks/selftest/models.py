"""Strict documents of the benchmark: the reviewed matrix and the aggregated result.

The matrix is the oracle's input and is written by hand; nothing here derives an expectation
from an observed verdict. The summary is a development artifact with its own schema, separate
from ``run.json``, and only counts what its cells say.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, model_validator

Mode: TypeAlias = Literal["tools", "agent"]
Language: TypeAlias = Literal["en", "pt"]
Framework: TypeAlias = Literal[
    "python", "anthropic", "openai-agents", "langgraph", "mcp-typescript", "typescript-native"
]
Variant: TypeAlias = Literal["vulnerable", "hardened", "no-tools", "mutant"]
CaseVariant: TypeAlias = Literal["vulnerable", "hardened", "no-tools"]
NativeState: TypeAlias = Literal[
    "finding", "resisted", "not_tested", "not_applicable", "conditional_risk"
]
Availability: TypeAlias = Literal["ready", "pending_dependency"]
Profile: TypeAlias = Literal["release", "full", "real"]
Status: TypeAlias = Literal["passed", "failed", "incomplete"]
Scope: TypeAlias = Literal["selection", "release", "full"]
Outcome: TypeAlias = Literal["passed", "failed", "pending", "error"]
CellKind: TypeAlias = Literal["target", "mutation", "check"]

Identifier = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]*$", max_length=80)]
Code = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$", max_length=80)]
ToolName = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$", max_length=64)]
# "<tool>#<record index>#<canary index>", with "-" for an absent part.
ScenarioKey = Annotated[
    str, Field(pattern=r"^(-|[a-z][a-z0-9_]*)#(-|[0-9]+)#(-|[0-9]+)$", max_length=100)
]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Text = Annotated[str, Field(min_length=1, max_length=500)]
StateMap: TypeAlias = dict[ScenarioKey, NativeState]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class FindingKey(_Strict):
    """A finding by meaning, comparable across targets and frameworks.

    ``tool`` is the canonical tool, or null for a signal the matrix declares tool independent.
    """

    mode: Mode
    mold_id: Identifier
    tool: ToolName | None
    signal: Code

    def sort_key(self) -> tuple[str, str, str, str]:
        return (self.mode, self.mold_id, self.tool or "", self.signal)


def sorted_keys(keys: Iterable[FindingKey]) -> list[FindingKey]:
    return sorted(set(keys), key=FindingKey.sort_key)


def scenario_tool(key: str) -> str | None:
    tool = key.split("#", 1)[0]
    return None if tool == "-" else tool


class Control(_Strict):
    """One control of the hardened target and what disabling it alone must show.

    ``changes`` replaces the hardened expectation of each listed mold; every other mold keeps
    its hardened expectation. ``representative`` is the single finding of the isolated case and
    ``full_scan`` the exact set of the whole catalog with this control off.
    """

    id: Identifier
    description: Text
    fixture_id: Identifier
    representative: FindingKey
    full_scan: list[FindingKey] = Field(min_length=1)
    changes: dict[Identifier, StateMap] = Field(min_length=1)


class FrameworkSupport(_Strict):
    """Whether an implementation of the shared domain can run, and what activates it."""

    id: Framework
    availability: Availability
    requirement: Text | None = None

    @model_validator(mode="after")
    def _reason(self) -> FrameworkSupport:
        if (self.availability == "pending_dependency") != (self.requirement is not None):
            raise ValueError(f"{self.id}: a pending framework needs a requirement, a ready none")
        return self


class AuxiliaryCheck(_Strict):
    """A verification that is not a target cell. ``tests`` is a reviewed explicit selection."""

    id: Identifier
    description: Text
    kind: Literal["builtin", "pytest"]
    tests: list[Annotated[str, Field(pattern=r"^tests/[a-z_/]+\.py$")]] = Field(
        default_factory=list[str]
    )

    @model_validator(mode="after")
    def _selection(self) -> AuxiliaryCheck:
        if (self.kind == "pytest") != bool(self.tests):
            raise ValueError(f"{self.id}: only a pytest check selects tests")
        return self


class BenchmarkCase(_Strict):
    """One mold on one implementation and variant, in each listed language."""

    case_id: Identifier
    mold_id: Identifier
    mode: Mode
    languages: list[Language] = Field(min_length=1)
    framework: Framework
    variant: CaseVariant
    fixture_id: Identifier
    expected_states: StateMap = Field(default_factory=dict[str, NativeState])
    availability: Availability
    dependency: Text | None = None

    @model_validator(mode="after")
    def _consistent(self) -> BenchmarkCase:
        if len(set(self.languages)) != len(self.languages):
            raise ValueError(f"{self.case_id}: repeated language")
        if self.availability == "ready":
            if not self.expected_states or self.dependency is not None:
                raise ValueError(f"{self.case_id}: a ready case has states and no dependency")
        elif self.dependency is None or self.expected_states:
            raise ValueError(f"{self.case_id}: a pending case has a dependency and no states")
        return self


class Matrix(_Strict):
    schema_version: Literal[1]
    revision: Text
    tool_independent_signals: list[Code] = Field(default_factory=list[str])
    controls: list[Control]
    frameworks: list[FrameworkSupport]
    checks: list[AuxiliaryCheck]
    cases: list[BenchmarkCase]

    @model_validator(mode="after")
    def _unique(self) -> Matrix:
        problems: list[str] = []
        for name, values in (
            ("case", [case.case_id for case in self.cases]),
            ("control", [control.id for control in self.controls]),
            ("framework", [item.id for item in self.frameworks]),
            ("check", [check.id for check in self.checks]),
            (
                "cell",
                [
                    f"{case.mold_id}/{case.mode}/{case.framework}/{case.variant}"
                    for case in self.cases
                ],
            ),
        ):
            repeated = sorted(name for name, count in Counter(values).items() if count > 1)
            problems.extend(f"duplicate {name}: {item}" for item in repeated)
        if problems:
            raise ValueError("; ".join(problems))
        return self

    def control(self, control_id: str) -> Control:
        return next(item for item in self.controls if item.id == control_id)

    def framework(self, framework: str) -> FrameworkSupport | None:
        return next((item for item in self.frameworks if item.id == framework), None)


class Provenance(_Strict):
    commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")] | None
    commit_unavailable: Code | None = None
    dirty: bool | None
    gazua_version: Text | None
    matrix_revision: Text
    matrix_digest: Digest
    catalog_digest: Digest
    runtime: Text
    dependencies: dict[Text, Text] = Field(default_factory=dict[str, str])
    model: Text | None = None

    @model_validator(mode="after")
    def _reason(self) -> Provenance:
        if (self.commit is None) != (self.commit_unavailable is not None):
            raise ValueError("a missing commit needs a reason")
        return self


class Counts(_Strict):
    expected_cells: Annotated[int, Field(ge=0)]
    passed_cells: Annotated[int, Field(ge=0)]
    failed_cells: Annotated[int, Field(ge=0)]
    pending_cells: Annotated[int, Field(ge=0)]
    error_cells: Annotated[int, Field(ge=0)]
    positive_expected: Annotated[int, Field(ge=0)]
    positive_detected: Annotated[int, Field(ge=0)]
    negative_expected: Annotated[int, Field(ge=0)]
    false_alarm_cells: Annotated[int, Field(ge=0)]
    unexpected_findings: Annotated[int, Field(ge=0)]
    controls_expected: Annotated[int, Field(ge=0)]
    controls_detected: Annotated[int, Field(ge=0)]


class CellResult(_Strict):
    """One cell's outcome. Pending and error cells say why; passed target cells name a run."""

    case_id: Identifier
    kind: CellKind
    mold_id: Identifier | None
    mode: Mode | None
    language: Language | None
    framework: Framework | None
    variant: Variant | None
    fixture_id: Identifier | None
    disabled_control: Identifier | None
    outcome: Outcome
    positive: bool = False
    negative: bool = False
    observed_states: StateMap = Field(default_factory=dict[str, NativeState])
    expected_findings: list[FindingKey] = Field(default_factory=list[FindingKey])
    observed_findings: list[FindingKey] = Field(default_factory=list[FindingKey])
    finding_ids: list[Annotated[str, Field(pattern=r"^finding-[0-9a-f]{64}$")]] = Field(
        default_factory=list[str]
    )
    run_document: Annotated[str, Field(max_length=300)] | None = None
    diagnostics: list[Code] = Field(default_factory=list[str])
    dependency: Text | None = None

    @model_validator(mode="after")
    def _consistent(self) -> CellResult:
        if (self.variant == "mutant") != (self.disabled_control is not None):
            raise ValueError(f"{self.case_id}: only a mutant names a disabled control")
        if self.outcome == "pending" and self.dependency is None:
            raise ValueError(f"{self.case_id}: a pending cell needs its dependency")
        if self.outcome == "error" and not self.diagnostics:
            raise ValueError(f"{self.case_id}: an error cell needs a diagnostic")
        if self.outcome == "passed" and self.kind != "check" and self.run_document is None:
            raise ValueError(f"{self.case_id}: a passed execution cell needs its run document")
        if self.positive and self.negative:
            raise ValueError(f"{self.case_id}: a cell is positive or negative, not both")
        if self.run_document is not None:
            relative_problem(self.run_document)
        return self

    def sort_key(self) -> tuple[str, str, str, str, str, str]:
        return (
            self.kind,
            self.case_id,
            self.framework or "",
            self.variant or "",
            self.disabled_control or "",
            self.language or "",
        )


def relative_problem(path: str) -> None:
    """Raises when a stored reference is absolute or leaves the benchmark folder."""
    pure = PurePosixPath(path)
    if not path or pure.is_absolute() or "\\" in path or ":" in path or ".." in pure.parts:
        raise ValueError(f"reference must stay inside the benchmark folder: {path!r}")


class BenchmarkSummary(_Strict):
    """``benchmark.json``. Counts are derived from the cells and checked again here."""

    model_config = ConfigDict(title="Gazua self-test benchmark result")

    schema_version: Literal[1]
    profile: Profile
    status: Status
    scope: Scope
    simulated: bool
    catalog_release: Annotated[str, Field(pattern=r"^(v[0-9]+\.[0-9]+|all)$")]
    provenance: Provenance
    counts: Counts
    cells: list[CellResult]
    gaps: list[Text] = Field(default_factory=list[str])
    artifacts: list[Annotated[str, Field(max_length=300)]]

    @model_validator(mode="after")
    def _consistent(self) -> BenchmarkSummary:
        for path in self.artifacts:
            relative_problem(path)
        if self.counts != count_cells(self.cells):
            raise ValueError("counts do not match the cells")
        identities = [cell.sort_key() for cell in self.cells]
        if len(set(identities)) != len(identities):
            raise ValueError("duplicate cell")
        if identities != sorted(identities):
            raise ValueError("cells are not in canonical order")
        if self.profile == "real" and self.simulated:
            raise ValueError("a real-model run is never simulated")
        if self.status == "passed" and (
            self.counts.failed_cells or self.counts.pending_cells or self.counts.error_cells
        ):
            raise ValueError("a passed result has no failed, pending or error cell")
        if self.scope == "full" and self.catalog_release != "all":
            raise ValueError("a full result covers every release")
        return self


def count_cells(cells: Iterable[CellResult]) -> Counts:
    items = list(cells)
    outcomes = Counter(cell.outcome for cell in items)
    targets = [cell for cell in items if cell.kind == "target"]
    mutations = [cell for cell in items if cell.kind == "mutation"]
    controls = {cell.disabled_control for cell in mutations}
    detected = {
        control
        for control in controls
        if all(cell.outcome == "passed" for cell in mutations if cell.disabled_control == control)
    }
    unexpected = 0
    for cell in targets:
        expected = {key.sort_key() for key in cell.expected_findings}
        unexpected += sum(1 for key in cell.observed_findings if key.sort_key() not in expected)
    return Counts(
        expected_cells=len(items),
        passed_cells=outcomes["passed"],
        failed_cells=outcomes["failed"],
        pending_cells=outcomes["pending"],
        error_cells=outcomes["error"],
        positive_expected=sum(1 for cell in targets if cell.positive),
        positive_detected=sum(1 for cell in targets if cell.positive and cell.outcome == "passed"),
        negative_expected=sum(1 for cell in targets if cell.negative),
        false_alarm_cells=sum(
            1
            for cell in targets
            if cell.negative and cell.outcome in ("passed", "failed") and cell.observed_findings
        ),
        unexpected_findings=unexpected,
        controls_expected=len(controls),
        controls_detected=len(detected),
    )


SCHEMA_FILE = Path(__file__).with_name("schemas") / "benchmark-v1.schema.json"


def build_benchmark_json_schema() -> dict[str, object]:
    return BenchmarkSummary.model_json_schema(mode="validation")


def render_benchmark_json_schema() -> str:
    return json.dumps(build_benchmark_json_schema(), indent=2) + "\n"


__all__ = [
    "SCHEMA_FILE",
    "AuxiliaryCheck",
    "BenchmarkCase",
    "BenchmarkSummary",
    "CellResult",
    "Control",
    "Counts",
    "FindingKey",
    "FrameworkSupport",
    "Matrix",
    "Provenance",
    "build_benchmark_json_schema",
    "count_cells",
    "relative_problem",
    "render_benchmark_json_schema",
    "scenario_tool",
    "sorted_keys",
]
