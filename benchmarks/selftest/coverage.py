"""Loads the reviewed matrix and checks it against the real catalog before anything runs.

Counts always come from the packaged manifest, never from constants here: a new mold without
its target pair, a control without its exact mutation mapping, or an expectation that points
to a missing mold makes the matrix invalid.
"""

from __future__ import annotations

import functools
import hashlib
import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Final, cast

from gazua.catalog.loader import RELEASES, CatalogEntry, Release, load_catalog, release_order
from gazua.catalog.models import Mold

from .models import BenchmarkCase, FindingKey, Matrix, StateMap, scenario_tool, sorted_keys

MATRIX_FILE: Final = Path(__file__).with_name("matrix.json")
REQUIRED_VARIANTS: Final = ("vulnerable", "hardened", "no-tools")


class MatrixError(Exception):
    """The matrix cannot be used; ``problems`` are short, safe descriptions."""

    def __init__(self, problems: Sequence[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = list(problems)


@dataclass(frozen=True, slots=True)
class Catalog:
    """Every packaged mold with the release that introduced it."""

    entries: tuple[CatalogEntry, ...]
    digest: str
    default_release: Release

    def mold(self, mold_id: str) -> Mold | None:
        return next((entry.mold for entry in self.entries if entry.id == mold_id), None)

    def release_of(self, mold_id: str) -> Release | None:
        return next((entry.introduced_in for entry in self.entries if entry.id == mold_id), None)

    def in_release(self, release: Release) -> list[CatalogEntry]:
        return [
            entry
            for entry in self.entries
            if entry.introduced_in is not None
            and release_order(entry.introduced_in) <= release_order(release)
        ]

    def introduced_in(self, release: Release) -> list[CatalogEntry]:
        return [entry for entry in self.entries if entry.introduced_in == release]


@functools.cache
def load_packaged_catalog() -> Catalog:
    """The installed catalog, read once per process; it cannot change while one runs."""
    loaded = load_catalog(release=RELEASES[-1])
    if loaded.has_errors:
        raise MatrixError(["the packaged catalog has errors"])
    folder = files("gazua").joinpath("catalog/builtin")
    manifest_text = folder.joinpath("manifest.json").read_text(encoding="utf-8")
    manifest = json.loads(manifest_text)
    digest = hashlib.sha256(manifest_text.encode("utf-8"))
    for item in manifest["molds"]:
        digest.update(folder.joinpath(item["file"]).read_bytes())
    return Catalog(loaded.entries, digest.hexdigest(), manifest["catalog_release"])


def load_matrix(path: Path = MATRIX_FILE) -> tuple[Matrix, str]:
    """The matrix and the SHA-256 of its bytes. Invalid content raises ``MatrixError``."""
    try:
        content = path.read_bytes()
    except OSError:
        raise MatrixError(["the matrix file cannot be read"]) from None
    try:
        document: object = json.loads(content)
    except ValueError:
        raise MatrixError(["the matrix is not valid JSON"]) from None
    version = (
        cast("dict[str, object]", document).get("schema_version")
        if isinstance(document, dict)
        else None
    )
    if version != 1:
        raise MatrixError(["unknown matrix schema_version; update the benchmark"])
    try:
        matrix = Matrix.model_validate_json(content)
    except ValueError as error:
        raise MatrixError([f"the matrix is invalid: {_first_line(error)}"]) from None
    return matrix, hashlib.sha256(content).hexdigest()


def _first_line(error: ValueError) -> str:
    return str(error).splitlines()[0][:200]


def canonical_tool(matrix: Matrix, signal: str, tool: str | None) -> str | None:
    return None if signal in matrix.tool_independent_signals else tool


def finding_keys(matrix: Matrix, mold: Mold, mode: str, states: StateMap) -> list[FindingKey]:
    """The findings a state map implies, by meaning: one per mold and canonical tool."""
    return sorted_keys(
        FindingKey.model_validate(
            {
                "mode": mode,
                "mold_id": mold.id,
                "tool": canonical_tool(matrix, mold.success.signal, scenario_tool(key)),
                "signal": mold.success.signal,
            }
        )
        for key, state in states.items()
        if state == "finding"
    )


def hardened_case(matrix: Matrix, mold_id: str, mode: str) -> BenchmarkCase | None:
    return next(
        (
            case
            for case in matrix.cases
            if case.mold_id == mold_id
            and case.mode == mode
            and case.framework == "python"
            and case.variant == "hardened"
        ),
        None,
    )


def coverage_problems(matrix: Matrix, catalog: Catalog) -> list[str]:
    problems: list[str] = []
    for case in matrix.cases:
        mold = catalog.mold(case.mold_id)
        if mold is None:
            problems.append(f"{case.case_id}: mold not in the catalog")
            continue
        if case.mode not in mold.supported_modes:
            problems.append(f"{case.case_id}: the mold does not support {case.mode}")
        if matrix.framework(case.framework) is None:
            problems.append(f"{case.case_id}: framework not in the support inventory")
        if case.availability != "ready":
            continue
        found = finding_keys(matrix, mold, case.mode, case.expected_states)
        if case.variant == "vulnerable" and not found:
            problems.append(f"{case.case_id}: the vulnerable target must fire")
        if case.variant != "vulnerable" and found:
            problems.append(f"{case.case_id}: only the vulnerable target may fire")
        if (
            case.variant == "no-tools"
            and case.mode == "tools"
            and set(case.expected_states.values()) != {"not_applicable"}
        ):
            problems.append(f"{case.case_id}: tools mode without tools is not applicable")
    for entry in catalog.entries:
        for mode in entry.mold.supported_modes:
            present = {
                case.variant
                for case in matrix.cases
                if case.mold_id == entry.id and case.mode == mode and case.framework == "python"
            }
            missing = [variant for variant in REQUIRED_VARIANTS if variant not in present]
            if missing:
                problems.append(f"{entry.id}: missing {', '.join(missing)} case in {mode}")
    problems.extend(_control_problems(matrix, catalog))
    return problems


def _control_problems(matrix: Matrix, catalog: Catalog) -> list[str]:
    problems: list[str] = []
    for control in matrix.controls:
        derived: list[FindingKey] = []
        for mold_id, states in control.changes.items():
            mold = catalog.mold(mold_id)
            base = hardened_case(matrix, mold_id, "tools")
            if mold is None or base is None or base.availability != "ready":
                problems.append(f"{control.id}: {mold_id} has no ready hardened case")
                continue
            derived.extend(finding_keys(matrix, mold, "tools", states))
        if sorted_keys(derived) != sorted_keys(control.full_scan):
            problems.append(f"{control.id}: full_scan differs from the declared changes")
        if control.representative not in control.full_scan:
            problems.append(f"{control.id}: the representative is not in full_scan")
        representative = catalog.mold(control.representative.mold_id)
        if representative is not None and (
            representative.success.signal != control.representative.signal
        ):
            problems.append(f"{control.id}: the representative signal differs from the mold")
    return problems


def changed_molds_problems(matrix: Matrix, changed: Iterable[str]) -> list[str]:
    """A changed mold must have its ready vulnerable and hardened pair on the reference target."""
    problems: list[str] = []
    for mold_id in sorted(set(changed)):
        ready = {
            case.variant
            for case in matrix.cases
            if case.mold_id == mold_id
            and case.framework == "python"
            and case.availability == "ready"
        }
        if not {"vulnerable", "hardened"} <= ready:
            problems.append(f"{mold_id}: changed mold without an executable target pair")
    return problems


__all__ = [
    "MATRIX_FILE",
    "Catalog",
    "MatrixError",
    "canonical_tool",
    "changed_molds_problems",
    "coverage_problems",
    "finding_keys",
    "hardened_case",
    "load_matrix",
    "load_packaged_catalog",
]
