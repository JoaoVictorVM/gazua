import json
import sys
from pathlib import Path
from typing import Any

from benchmarks.selftest.checks import PAYLOAD_MARKERS, html_problems, xss_check
from benchmarks.selftest.storage import contained

from conftest import run_process
from gazua.reports.storage import load_run_document


def vulnerable(outcome: Any) -> list[Path]:
    return sorted(
        path
        for path in (outcome.folder / "runs").iterdir()
        if path.name.startswith("tools-python-vulnerable")
    )


def test_results_and_persisted_findings_agree(benchmark_selection: Any) -> None:
    cells = [cell for cell in benchmark_selection.summary.cells if cell.run_document]
    assert cells
    for cell in cells:
        document = load_run_document(contained(benchmark_selection.folder, cell.run_document))
        stored = {item.id for item in document.findings if item.mold_id == cell.mold_id}
        if cell.kind == "target":
            assert set(cell.finding_ids) == stored
        for finding in document.findings:
            assert finding.proof_ids
            assert set(finding.proof_ids) <= {proof.id for proof in document.proofs}
    for path in vulnerable(benchmark_selection):
        document = load_run_document(path / ".gazua" / "run.json")
        assert document.report_exit_code == 1
        # The gate the CLI uses comes from the same verdicts the benchmark judged.
        assert document.verdicts.has_gated_findings


def test_payload_remains_inert_in_html(benchmark_selection: Any) -> None:
    assert xss_check(vulnerable(benchmark_selection)).outcome == "passed"
    hostile = '<html><head></head><body><b data-gazua="marker" onclick="x()">x</b>'
    assert {"payload_tag_rendered", "event_handler_attribute", "csp_missing"} <= set(
        html_problems(hostile)
    )


def test_regeneration_preserves_security(benchmark_selection: Any) -> None:
    project = vulnerable(benchmark_selection)[0]
    for name in ("report.html", "report.md"):
        (project / ".gazua" / name).unlink()
    result = run_process(
        [sys.executable, "-m", "gazua", "report", "--from", ".gazua/run.json"], cwd=project
    )
    assert result.returncode in (0, 1), result.stderr
    html = (project / ".gazua" / "report.html").read_text(encoding="utf-8")
    assert html_problems(html) == []
    assert "GAZUA-OUTPUT-MARKER" in html


def test_summary_omits_payloads(benchmark_selection: Any) -> None:
    text = (benchmark_selection.folder / "benchmark.json").read_text(encoding="utf-8")
    summary = json.loads(text)
    for marker in PAYLOAD_MARKERS:
        assert marker not in text
    for cell in summary["cells"]:
        assert set(cell) >= {"case_id", "outcome", "observed_states", "diagnostics"}
        assert "payload" not in cell
        assert "attack" not in cell
