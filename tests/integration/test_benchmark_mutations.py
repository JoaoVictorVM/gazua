from typing import Any

from benchmarks.selftest.coverage import load_matrix


def mutations(outcome: Any, kind: str) -> dict[str, Any]:
    return {
        cell.disabled_control: cell
        for cell in outcome.summary.cells
        if cell.kind == "mutation" and cell.case_id.endswith(f"-{kind}")
    }


def test_one_disabled_control_has_exact_delta(benchmark_selection: Any) -> None:
    matrix, _ = load_matrix()
    isolated = mutations(benchmark_selection, "isolated")
    # The selection keeps every control whose representative mold it includes.
    assert set(isolated) == {
        "order-ownership",
        "invoice-ownership",
        "note-ownership",
        "note-minimization",
        "sensitive-operation",
    }
    for control_id, cell in isolated.items():
        control = matrix.control(control_id)
        assert cell.outcome == "passed", (control_id, cell.diagnostics)
        assert cell.variant == "mutant"
        assert cell.expected_findings == [control.representative]
        assert cell.observed_findings == [control.representative]


def test_other_controls_stay_effective(benchmark_selection: Any) -> None:
    isolated = mutations(benchmark_selection, "isolated")
    seen = [key for cell in isolated.values() for key in cell.observed_findings]
    # Each isolated case shows its own control only: no finding is shared between them.
    assert len(seen) == len(set(seen)) == len(isolated)


def test_full_scan_matches_control_mapping(benchmark_selection: Any) -> None:
    matrix, _ = load_matrix()
    full = mutations(benchmark_selection, "full")
    for control_id, cell in full.items():
        control = matrix.control(control_id)
        assert cell.outcome == "passed", (control_id, cell.diagnostics)
        selected = [
            key
            for key in control.full_scan
            if key.mold_id in {"idor-01", "idor-04", "secret-01", "permission-03", "output-02"}
        ]
        assert sorted(cell.observed_findings, key=lambda key: key.sort_key()) == sorted(
            selected, key=lambda key: key.sort_key()
        )
    # An ownership control maps to several findings in the whole scan, one per mold.
    assert len(full["invoice-ownership"].observed_findings) == 2
    counts = benchmark_selection.summary.counts
    assert counts.controls_expected == counts.controls_detected == 5
