import json
from pathlib import Path
from typing import Any

import pytest
from benchmarks.selftest.coverage import (
    MATRIX_FILE,
    MatrixError,
    changed_molds_problems,
    coverage_problems,
    finding_keys,
    load_matrix,
    load_packaged_catalog,
)
from benchmarks.selftest.models import Matrix


@pytest.fixture(scope="module")
def document() -> dict[str, Any]:
    return json.loads(MATRIX_FILE.read_text(encoding="utf-8"))


def matrix_of(document: dict[str, Any]) -> Matrix:
    return Matrix.model_validate_json(json.dumps(document))


def test_every_release_mold_has_target_pair() -> None:
    matrix, _ = load_matrix()
    catalog = load_packaged_catalog()

    assert coverage_problems(matrix, catalog) == []
    for release in ("v0.1", "v0.2", "v0.4"):
        for entry in catalog.introduced_in(release):
            variants = {
                case.variant
                for case in matrix.cases
                if case.mold_id == entry.id and case.framework == "python"
            }
            assert variants == {"vulnerable", "hardened", "no-tools"}, entry.id
    # The default release gate needs every one of its molds ready, never pending.
    for entry in catalog.in_release(catalog.default_release):
        ready = {
            case.variant
            for case in matrix.cases
            if case.mold_id == entry.id and case.availability == "ready"
        }
        assert ready == {"vulnerable", "hardened", "no-tools"}, entry.id


def test_new_mold_requires_live_checks(document: dict[str, Any]) -> None:
    matrix, _ = load_matrix()
    assert changed_molds_problems(matrix, ["idor-01", "secret-02"]) == []

    pending = [case["mold_id"] for case in document["cases"] if case["availability"] != "ready"]
    assert changed_molds_problems(matrix, [pending[0]]) == [
        f"{pending[0]}: changed mold without an executable target pair"
    ]
    assert changed_molds_problems(matrix, ["new-mold-99"]) == [
        "new-mold-99: changed mold without an executable target pair"
    ]

    catalog = load_packaged_catalog()
    without_pair = dict(document)
    without_pair["cases"] = [
        case
        for case in document["cases"]
        if not (case["mold_id"] == "idor-02" and case["variant"] == "hardened")
    ]
    assert "idor-02: missing hardened case in tools" in coverage_problems(
        matrix_of(without_pair), catalog
    )


def test_each_control_has_one_mutation(document: dict[str, Any]) -> None:
    matrix, _ = load_matrix()
    catalog = load_packaged_catalog()
    assert matrix.controls
    for control in matrix.controls:
        assert control.representative in control.full_scan
        mold = catalog.mold(control.representative.mold_id)
        assert mold is not None
        changed = control.changes[mold.id]
        assert control.representative in finding_keys(matrix, mold, "tools", changed)

    broken = json.loads(json.dumps(document))
    broken["controls"][0]["full_scan"] = broken["controls"][0]["full_scan"][:1]
    problems = coverage_problems(matrix_of(broken), catalog)
    assert f"{broken['controls'][0]['id']}: full_scan differs from the declared changes" in problems


def test_quiet_and_firing_expectations_are_enforced(document: dict[str, Any]) -> None:
    catalog = load_packaged_catalog()
    quiet = json.loads(json.dumps(document))
    case = next(
        item for item in quiet["cases"] if item["case_id"] == "idor-01-tools-python-vulnerable"
    )
    case["expected_states"] = dict.fromkeys(case["expected_states"], "resisted")
    loud = next(
        item for item in quiet["cases"] if item["case_id"] == "idor-01-tools-python-hardened"
    )
    loud["expected_states"]["get_order#0#-"] = "finding"

    problems = coverage_problems(matrix_of(quiet), catalog)

    assert "idor-01-tools-python-vulnerable: the vulnerable target must fire" in problems
    assert "idor-01-tools-python-hardened: only the vulnerable target may fire" in problems


def test_unknown_and_duplicate_cases_fail(document: dict[str, Any], tmp_path: Path) -> None:
    catalog = load_packaged_catalog()
    unknown = json.loads(json.dumps(document))
    unknown["cases"][0] = {**unknown["cases"][0], "mold_id": "idor-99", "case_id": "idor-99-x"}
    assert "idor-99-x: mold not in the catalog" in coverage_problems(matrix_of(unknown), catalog)

    duplicate = json.loads(json.dumps(document))
    duplicate["cases"].append(dict(duplicate["cases"][0]))
    with pytest.raises(ValueError, match="duplicate case"):
        matrix_of(duplicate)

    newer = tmp_path / "matrix.json"
    newer.write_text(json.dumps({**document, "schema_version": 2}), encoding="utf-8")
    with pytest.raises(MatrixError, match="update the benchmark"):
        load_matrix(newer)

    garbage = tmp_path / "garbage.json"
    garbage.write_text("{", encoding="utf-8")
    with pytest.raises(MatrixError, match="not valid JSON"):
        load_matrix(garbage)


def test_pending_cases_need_a_reason(document: dict[str, Any]) -> None:
    pending = json.loads(json.dumps(document))
    case = next(item for item in pending["cases"] if item["availability"] != "ready")
    case.pop("dependency")
    with pytest.raises(ValueError, match="a pending case has a dependency"):
        matrix_of(pending)
