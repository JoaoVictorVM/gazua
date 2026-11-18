from typing import Any

import pytest
from benchmarks.selftest.coverage import load_matrix, load_packaged_catalog
from benchmarks.selftest.models import FindingKey, Matrix
from benchmarks.selftest.oracle import (
    RunObservation,
    judge,
    mutation_delta,
    normalized_scenarios,
    parity_problems,
    run_problems,
)
from report_factory import document

from gazua.catalog.models import Mold
from gazua.reports.models import RunDocument


@pytest.fixture(scope="module")
def matrix() -> Matrix:
    return load_matrix()[0]


@pytest.fixture(scope="module")
def run() -> RunDocument:
    return document()


def mold(mold_id: str) -> Mold:
    found = load_packaged_catalog().mold(mold_id)
    assert found is not None
    return found


def observe(run: RunDocument, **overrides: Any) -> RunObservation:
    fields: dict[str, Any] = {
        "label": "tools-python-vulnerable-en",
        "exit_code": run.report_exit_code,
        "run_document": "runs/x/run.json",
        "document": run,
        "native_states": {item.attack_key: item.state for item in run.verdicts.results},
    }
    fields.update(overrides)
    return RunObservation(**fields)


def test_exact_semantic_findings_required(matrix: Matrix, run: RunDocument) -> None:
    observation = observe(run)
    assert run_problems(observation) == []

    passed = judge(
        {"delete_account#-#-": "not_applicable"},
        observation,
        matrix,
        mold("permission-01"),
        "tools",
    )
    assert passed.outcome == "passed"
    assert passed.expected_findings == passed.observed_findings == []

    wanted = judge(
        {"delete_account#-#-": "finding"}, observation, matrix, mold("permission-01"), "tools"
    )
    assert wanted.outcome == "failed"
    assert "missing_findings" in wanted.diagnostics
    assert "expected_finding_observed_not_applicable" in wanted.diagnostics


def test_same_count_wrong_finding_fails(matrix: Matrix, run: RunDocument) -> None:
    # One expected finding, one observed finding: the count agrees, the identity does not.
    verdict = judge({"get_invoice#0#-": "finding"}, observe(run), matrix, mold("idor-02"), "tools")

    assert len(verdict.expected_findings) == len(verdict.observed_findings) == 1
    assert verdict.outcome == "failed"
    assert {"missing_findings", "unexpected_findings", "missing_scenario"} <= set(
        verdict.diagnostics
    )
    # Two scenarios that share one key can never be judged as one.
    assert "ambiguous_scenario" in verdict.diagnostics


def test_incomplete_is_never_resisted(matrix: Matrix, run: RunDocument) -> None:
    verdict = judge(
        {"refund#-#-": "resisted"}, observe(run), matrix, mold("permission-03"), "tools"
    )

    assert verdict.outcome == "failed"
    assert verdict.observed_states == {"refund#-#-": "not_tested"}
    assert verdict.diagnostics == ["expected_resisted_observed_not_tested"]


def test_operational_errors_win_over_mismatch(matrix: Matrix, run: RunDocument) -> None:
    broken = observe(run, exit_code=2, operational=("rate_limited",))
    verdict = judge({"refund#-#-": "resisted"}, broken, matrix, mold("permission-03"), "tools")
    assert verdict.outcome == "error"
    assert "rate_limited" in verdict.diagnostics

    missing = judge(
        {"refund#-#-": "not_tested"},
        observe(run, document=None, error="report_not_saved"),
        matrix,
        mold("permission-03"),
        "tools",
    )
    assert missing.outcome == "error"
    assert missing.diagnostics == ["report_not_saved"]


def test_persisted_report_must_match_native_result(run: RunDocument) -> None:
    states = {item.attack_key: item.state for item in run.verdicts.results}
    flipped = {key: ("resisted" if state == "finding" else state) for key, state in states.items()}

    problems = run_problems(observe(run, native_states=flipped))

    assert problems == ["native_report_mismatch"]


def test_framework_normalization_preserves_conditions(run: RunDocument) -> None:
    elsewhere = document(target="other_entry:main")
    assert {item.id for item in elsewhere.findings} != {item.id for item in run.findings}
    for mold_id in ("idor-02", "permission-03", "output-03"):
        assert (
            parity_problems(
                normalized_scenarios(run, mold_id), normalized_scenarios(elsewhere, mold_id)
            )
            == []
        )

    reference = normalized_scenarios(run, "output-03")
    weaker = {key: {**value, "low_fidelity": True} for key, value in reference.items()}
    assert parity_problems(reference, weaker) == ["-#-#-: low_fidelity differs"]
    assert reference["-#-#-"]["state"] == "conditional_risk"
    assert parity_problems(reference, {}) == ["-#-#-: present in one implementation only"]

    proven = normalized_scenarios(run, "permission-03")
    proven["refund#-#-"] = {**proven["refund#-#-"], "conditions": ["dry_run"]}
    assert parity_problems(normalized_scenarios(run, "permission-03"), proven) == [
        "refund#-#-: conditions differs"
    ]


def test_mutation_delta_is_a_set_difference() -> None:
    key = FindingKey(
        mode="tools", mold_id="idor-01", tool="get_order", signal="victim_record_access"
    )
    other = FindingKey(
        mode="tools", mold_id="idor-01", tool="get_note", signal="victim_record_access"
    )

    assert mutation_delta([key, other], [other]) == [key]
    assert mutation_delta([key, key], []) == [key]
    assert mutation_delta([other], [other]) == []
