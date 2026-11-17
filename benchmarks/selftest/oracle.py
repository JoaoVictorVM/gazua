"""Compares what Gazua persisted with the reviewed expectations, without changing either.

The oracle reads only the reopened run document and the native result of the same run. It
never edits a verdict or a finding: a mismatch, a missing proof, an incomplete run or an extra
finding fails the cell even when the counts happen to agree.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from gazua.catalog.models import Mold
from gazua.reports.models import RunDocument, Scenario

from .coverage import canonical_tool, finding_keys
from .models import FindingKey, Matrix, NativeState, Outcome, StateMap, sorted_keys


@dataclass(frozen=True, slots=True)
class RunObservation:
    """One native run as the benchmark saw it, before any cell is judged."""

    label: str
    exit_code: int
    run_document: str | None = None
    document: RunDocument | None = None
    native_states: Mapping[str, str] = field(default_factory=dict[str, str])
    operational: tuple[str, ...] = ()
    error: str | None = None


@dataclass(frozen=True, slots=True)
class Judgement:
    outcome: Outcome
    observed_states: StateMap
    expected_findings: list[FindingKey]
    observed_findings: list[FindingKey]
    finding_ids: list[str]
    diagnostics: list[str]


def scenario_key(scenario: Scenario) -> str:
    def part(value: object) -> str:
        return "-" if value is None else str(value)

    return f"{part(scenario.tool_name)}#{part(scenario.record_index)}#{part(scenario.canary_index)}"


def run_problems(observation: RunObservation) -> list[str]:
    """Codes of disagreements between the native result and the persisted document."""
    document = observation.document
    if document is None:
        return [observation.error or "run_document_missing"]
    problems: list[str] = []
    persisted = {result.attack_key: result.state for result in document.verdicts.results}
    if persisted != dict(observation.native_states):
        problems.append("native_report_mismatch")
    proofs = {proof.id for proof in document.proofs}
    reported: set[str] = set()
    for finding in document.findings:
        if not finding.proof_ids or not set(finding.proof_ids) <= proofs:
            problems.append("proof_missing")
        for key in finding.scenarios:
            reported.add(key)
            if persisted.get(key) != "finding":
                problems.append("finding_without_proven_scenario")
    proven = {key for key, state in persisted.items() if state == "finding"}
    if proven != reported:
        problems.append("finding_not_reported")
    for item in document.proofs:
        if persisted.get(item.attack_key) != "finding":
            problems.append("proof_for_unproven_scenario")
    return sorted(set(problems))


def mold_states(document: RunDocument, mold_id: str) -> tuple[dict[str, NativeState], bool]:
    """Scenario states of one mold, and whether two scenarios shared a key."""
    states: dict[str, NativeState] = {}
    repeated = False
    results = {result.attack_key: result for result in document.verdicts.results}
    for scenario in document.scenarios:
        if scenario.mold_id != mold_id:
            continue
        key = scenario_key(scenario)
        repeated = repeated or key in states
        states[key] = results[scenario.attack_key].state
    return states, repeated


def mold_findings(
    document: RunDocument, matrix: Matrix, mold: Mold
) -> tuple[list[FindingKey], list[str], set[tuple[str, str | None]]]:
    """Semantic keys, local ids and native (mold, tool) identities of one mold's findings."""
    keys: list[FindingKey] = []
    ids: list[str] = []
    native: set[tuple[str, str | None]] = set()
    for finding in document.findings:
        if finding.mold_id != mold.id:
            continue
        ids.append(finding.id)
        native.add((finding.mold_id, finding.tool_name))
        keys.append(
            FindingKey(
                mode=finding.mode,
                mold_id=finding.mold_id,
                tool=canonical_tool(matrix, mold.success.signal, finding.tool_name),
                signal=mold.success.signal,
            )
        )
    return sorted_keys(keys), sorted(ids), native


def state_diagnostics(expected: Mapping[str, str], observed: Mapping[str, str]) -> list[str]:
    found: list[str] = []
    for key in sorted(set(expected) | set(observed)):
        if key not in observed:
            found.append("missing_scenario")
        elif key not in expected:
            found.append("unexpected_scenario")
        elif expected[key] != observed[key]:
            found.append(f"expected_{expected[key]}_observed_{observed[key]}")
    return found


def judge(
    expected: StateMap,
    observation: RunObservation,
    matrix: Matrix,
    mold: Mold,
    mode: str,
    problems: Sequence[str] = (),
) -> Judgement:
    """The outcome of one cell. Operational errors win over mismatches."""
    expected_keys = finding_keys(matrix, mold, mode, expected)
    document = observation.document
    if document is None or observation.exit_code == 2:
        codes = [observation.error or "run_operational_error", *observation.operational]
        return Judgement("error", {}, expected_keys, [], [], sorted(set(codes)))
    observed, repeated = mold_states(document, mold.id)
    keys, ids, native = mold_findings(document, matrix, mold)
    diagnostics = [*problems, *state_diagnostics(expected, observed)]
    if repeated:
        diagnostics.append("ambiguous_scenario")
    proven = {
        (mold.id, None if key.startswith("-#") else key.split("#", 1)[0])
        for key, state in observed.items()
        if state == "finding"
    }
    if proven != native:
        diagnostics.append("findings_differ_from_scenarios")
    if keys != expected_keys:
        diagnostics.append("unexpected_findings" if set(keys) - set(expected_keys) else "")
        diagnostics.append("missing_findings" if set(expected_keys) - set(keys) else "")
    diagnostics = sorted({code for code in diagnostics if code})
    outcome: Outcome = "failed" if diagnostics else "passed"
    return Judgement(outcome, observed, expected_keys, keys, ids, diagnostics)


def mutation_delta(
    observed: Sequence[FindingKey], baseline: Sequence[FindingKey]
) -> list[FindingKey]:
    return sorted_keys(set(observed) - set(baseline))


def normalized_scenarios(document: RunDocument, mold_id: str) -> dict[str, dict[str, Any]]:
    """What must match across implementations: never ids, paths or the target reference.

    Conditions, low fidelity, coverage and reason codes stay, so a framework that proves less
    is visible as a difference instead of being washed into parity.
    """
    results = {result.attack_key: result for result in document.verdicts.results}
    found: dict[str, dict[str, Any]] = {}
    for scenario in document.scenarios:
        if scenario.mold_id != mold_id:
            continue
        result = results[scenario.attack_key]
        found[scenario_key(scenario)] = {
            "state": result.state,
            "coverage": result.coverage,
            "low_fidelity": result.low_fidelity,
            "conditions": sorted({item for proof in result.proof for item in proof.conditions}),
            "signals": sorted({proof.signal for proof in result.proof}),
            "reasons": sorted({reason.code for reason in result.reasons}),
            "errors": sorted(result.operational_errors),
        }
    return found


def parity_problems(
    reference: Mapping[str, Mapping[str, Any]], other: Mapping[str, Mapping[str, Any]]
) -> list[str]:
    problems: list[str] = []
    for key in sorted(set(reference) | set(other)):
        if key not in reference or key not in other:
            problems.append(f"{key}: present in one implementation only")
            continue
        for name in sorted(set(reference[key]) | set(other[key])):
            if reference[key].get(name) != other[key].get(name):
                problems.append(f"{key}: {name} differs")
    return problems


__all__ = [
    "Judgement",
    "RunObservation",
    "judge",
    "mold_findings",
    "mold_states",
    "mutation_delta",
    "normalized_scenarios",
    "parity_problems",
    "run_problems",
    "scenario_key",
    "state_diagnostics",
]
