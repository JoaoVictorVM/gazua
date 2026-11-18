import json
from pathlib import Path
from typing import Any

from benchmarks.selftest.checks import legitimate_check
from benchmarks.selftest.coverage import load_packaged_catalog
from benchmarks.selftest.runner import BenchmarkOptions, prepare_workspace, run_benchmark
from benchmarks.selftest.targets.domain import DomainData, Profile

from conftest import BENCHMARK_SELECTION

DOMAIN = Path(__file__).resolve().parents[2] / "benchmarks/selftest/fixtures/domain.json"


def targets(outcome: Any, variant: str) -> list[Any]:
    return [
        cell for cell in outcome.summary.cells if cell.kind == "target" and cell.variant == variant
    ]


def test_each_mold_fires_and_hardened_is_quiet(benchmark_selection: Any) -> None:
    summary = benchmark_selection.summary
    assert benchmark_selection.exit_code == 0, [
        (cell.case_id, cell.language, cell.diagnostics)
        for cell in summary.cells
        if cell.outcome != "passed"
    ]
    assert summary.status == "passed"
    assert summary.scope == "selection"
    for language in ("en", "pt"):
        fired = {
            cell.mold_id
            for cell in targets(benchmark_selection, "vulnerable")
            if cell.language == language and cell.observed_findings
        }
        assert fired == set(BENCHMARK_SELECTION)
    for cell in targets(benchmark_selection, "hardened"):
        assert cell.observed_findings == []
        assert cell.finding_ids == []
        assert "finding" not in cell.observed_states.values()
    assert summary.counts.false_alarm_cells == 0
    assert summary.counts.positive_detected == summary.counts.positive_expected > 0


def test_no_tools_is_proven_inapplicable(benchmark_selection: Any) -> None:
    cells = targets(benchmark_selection, "no-tools")
    assert {cell.mold_id for cell in cells} == set(BENCHMARK_SELECTION)
    for cell in cells:
        assert cell.observed_states == {"-#-#-": "not_applicable"}
        assert not cell.positive
        assert not cell.negative
    run = benchmark_selection.folder / cells[0].run_document
    document = json.loads(run.read_text(encoding="utf-8"))
    # A proven empty target is not an operational error: zero calls, exit 0.
    assert document["report_exit_code"] == 0
    assert document["engine"]["started"] == 0


def test_legitimate_tasks_still_work(tmp_path: Path) -> None:
    data = DomainData.load(DOMAIN)
    hardened = prepare_workspace(tmp_path / "hardened", Profile.build("hardened"), data)
    assert legitimate_check(hardened).outcome == "passed"

    # A target that refuses everything is caught: the vulnerable store has no such problem,
    # so break the hardened one by hiding the user's own records.
    broken = prepare_workspace(tmp_path / "broken", Profile.build("hardened"), data)
    domain = broken / "selftest_target" / "domain.json"
    document = json.loads(domain.read_text(encoding="utf-8"))
    for table in ("orders", "invoices", "notes"):
        for item in document[table]:
            item["user_id"] = "someone-else"
    domain.write_text(json.dumps(document), encoding="utf-8")
    result = legitimate_check(broken)
    assert result.outcome == "failed"
    assert "legitimate_task_refused" in result.diagnostics


def test_vulnerable_catalog_counts_come_from_the_manifest(benchmark_selection: Any) -> None:
    catalog = load_packaged_catalog()
    release = {entry.id for entry in catalog.in_release(catalog.default_release)}
    assert set(BENCHMARK_SELECTION) <= release
    expected = {
        (cell.case_id, cell.language)
        for cell in benchmark_selection.summary.cells
        if cell.kind == "target"
    }
    assert len(expected) == len(BENCHMARK_SELECTION) * 3 * 2


def test_broken_expectation_fails_the_benchmark(tmp_path: Path) -> None:
    matrix_file = Path(__file__).resolve().parents[2] / "benchmarks/selftest/matrix.json"
    document = json.loads(matrix_file.read_text(encoding="utf-8"))
    case = next(
        item for item in document["cases"] if item["case_id"] == "secret-01-tools-python-vulnerable"
    )
    case["expected_states"]["get_order#0#0"] = "finding"
    broken = tmp_path / "matrix.json"
    broken.write_text(json.dumps(document), encoding="utf-8")

    outcome = run_benchmark(
        BenchmarkOptions(molds=["secret-01"], output=str(tmp_path / "out")),
        root=tmp_path,
        say=lambda _line: None,
        matrix_path=broken,
    )

    assert outcome.exit_code == 1
    assert outcome.summary.status == "failed"
    failed = [cell for cell in outcome.summary.cells if cell.outcome == "failed"]
    assert {cell.case_id for cell in failed} == {"secret-01-tools-python-vulnerable"}
    assert all("missing_findings" in cell.diagnostics for cell in failed)
    assert (outcome.folder / "benchmark.json").is_file()
