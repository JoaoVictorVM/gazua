from typing import Any

from benchmarks.selftest.metrics import NOT_APPLICABLE, Rate, controls, rows
from benchmarks.selftest.models import CellResult, FindingKey, count_cells

KEY = {"mode": "tools", "mold_id": "idor-01", "tool": "get_order", "signal": "victim_record_access"}


def cell(**overrides: Any) -> CellResult:
    document: dict[str, Any] = {
        "case_id": "idor-01-tools-python-vulnerable",
        "kind": "target",
        "mold_id": "idor-01",
        "mode": "tools",
        "language": "en",
        "framework": "python",
        "variant": "vulnerable",
        "fixture_id": "victim-records",
        "disabled_control": None,
        "outcome": "passed",
        "run_document": "runs/x/run.json",
    }
    document.update(overrides)
    return CellResult.model_validate(document)


def mutation(control: str, outcome: str, kind: str = "isolated") -> CellResult:
    return cell(
        case_id=f"mutation-{control}-{kind}",
        kind="mutation",
        variant="mutant",
        disabled_control=control,
        outcome=outcome,
    )


def test_pending_remains_in_coverage_denominator() -> None:
    cells = [
        cell(positive=True, expected_findings=[KEY], observed_findings=[KEY]),
        cell(
            case_id="idor-02-tools-python-vulnerable",
            outcome="pending",
            run_document=None,
            dependency="adapter",
        ),
        cell(
            case_id="idor-03-tools-python-vulnerable",
            outcome="error",
            run_document=None,
            diagnostics=["interrupted"],
        ),
    ]
    [row] = rows(cells)
    assert row.coverage == Rate(1, 3)
    assert (row.pending, row.errors) == (1, 1)
    counts = count_cells(cells)
    assert counts.expected_cells == 3
    assert counts.pending_cells == counts.error_cells == 1


def test_not_applicable_is_not_negative_sample() -> None:
    quiet = cell(variant="hardened", negative=True, observed_states={"get_order#0#-": "resisted"})
    absent = cell(
        case_id="permission-01-tools-python-no-tools",
        variant="no-tools",
        observed_states={"-#-#-": "not_applicable"},
    )
    counts = count_cells([quiet, absent])
    assert counts.negative_expected == 1
    assert counts.false_alarm_cells == 0
    loud = cell(variant="hardened", negative=True, outcome="failed", observed_findings=[KEY])
    assert count_cells([loud]).false_alarm_cells == 1
    assert count_cells([loud]).unexpected_findings == 1


def test_zero_denominator_is_absent() -> None:
    assert Rate(0, 0).value is None
    assert Rate(0, 0).text() == NOT_APPLICABLE
    assert Rate(0, 4).text() == "0.0% (0/4)"
    assert Rate(2, 3).text() == "66.7% (2/3)"
    [row] = rows([cell(variant="no-tools", observed_states={"-#-#-": "not_applicable"})])
    assert row.detection.text() == NOT_APPLICABLE
    assert row.false_alarms.text() == NOT_APPLICABLE


def test_mutations_count_unique_controls() -> None:
    cells = [
        mutation("order-ownership", "passed"),
        mutation("order-ownership", "passed", "full"),
        cell(
            case_id="mutation-order-ownership-isolated",
            kind="mutation",
            variant="mutant",
            disabled_control="order-ownership",
            language="pt",
        ),
        mutation("note-minimization", "passed"),
        mutation("note-minimization", "failed", "full"),
    ]
    counts = count_cells(cells)
    # Languages and repeated cases never multiply a control; one failing case loses it.
    assert counts.controls_expected == 2
    assert counts.controls_detected == 1
    assert controls(counts).text() == "50.0% (1/2)"


def test_positive_with_extra_finding_is_not_detected() -> None:
    other = FindingKey.model_validate({**KEY, "tool": "get_note"})
    extra = cell(
        positive=True,
        outcome="failed",
        expected_findings=[KEY],
        observed_findings=[KEY, other],
    )
    counts = count_cells([extra])
    assert counts.positive_expected == 1
    assert counts.positive_detected == 0
    assert counts.unexpected_findings == 1
