import sys
from pathlib import Path
from typing import Any

from report_factory import document
from report_support import gazua, local_environment, read_json

from conftest import run_process
from gazua.reports.storage import document_json

STATES = ("finding", "conditional_risk", "resisted", "not_tested", "not_applicable")


def test_finding_has_severity_attack_proof_reproduction_and_fix(tools_project: Any) -> None:
    (tools_project.root / ".gitignore").write_text(".gazua/\n", encoding="utf-8")
    first = tools_project.cli("--tools", "--mold", "idor-01", env=local_environment())

    assert first.returncode == 1, first.stderr
    run = read_json(tools_project.root / ".gazua" / "run.json")
    assert len(run["findings"]) == 1
    finding = run["findings"][0]
    assert finding["severity"] == "high"
    assert finding["damage"] == "idor_via_agent"
    assert finding["attack"].startswith("Direct access to the declared victim record")
    assert finding["conditions"]
    assert finding["fix_ref"] == "idor_via_agent"
    assert finding["fix"]
    proofs = {item["id"]: item for item in run["proofs"]}
    proof = proofs[finding["proof_ids"][0]]
    assert proof["source"] == "tool_return"
    assert proof["content"]["original"]["user_id"] == "victim-1"
    assert proof["content"]["original"]["note"] == "GAZUA-CANARY-7f3a9c"
    reproduction = finding["reproduction"]
    assert reproduction["available"] is True
    assert reproduction["argv"] == [
        "gazua",
        "run",
        "--tools",
        "--config",
        "gazua.yaml",
        "--mold",
        "idor-01",
    ]
    assert reproduction["cwd"] == "."
    assert "Reproduce: gazua run --tools --config gazua.yaml --mold idor-01" in first.stdout
    assert "Reports: .gazua/report.html, .gazua/report.md, .gazua/run.json" in first.stdout
    html = (tools_project.root / ".gazua" / "report.html").read_text(encoding="utf-8")
    assert finding["id"] in html
    assert 'id="fix-idor_via_agent"' in html

    command = [sys.executable, "-m", "gazua", *reproduction["argv"][1:]]
    again = run_process(
        command, cwd=tools_project.root / reproduction["cwd"], env=local_environment()
    )

    assert again.returncode == 1, again.stderr
    rerun = read_json(tools_project.root / ".gazua" / "run.json")
    assert rerun["run_id"] != run["run_id"]
    assert [item["id"] for item in rerun["findings"]] == [finding["id"]]
    assert rerun["findings"][0]["scenarios"] == finding["scenarios"]


def test_reports_include_every_state_and_missing_reason(tmp_path: Path) -> None:
    built = document()
    source = tmp_path / "source" / "run.json"
    source.parent.mkdir()
    source.write_text(document_json(built), encoding="utf-8")
    work = tmp_path / "work"
    work.mkdir()

    result = gazua(work, "report", "--from", str(source))

    assert result.returncode == 0, result.stderr
    run = read_json(work / ".gazua" / "run.json")
    html = (work / ".gazua" / "report.html").read_text(encoding="utf-8")
    markdown = (work / ".gazua" / "report.md").read_text(encoding="utf-8")
    assert sorted(item["state"] for item in run["verdicts"]["results"]) == sorted(STATES)
    for text in (html, markdown, result.stdout):
        assert "not tested" in text
        assert "receiver unavailable" in text
        assert "not applicable" in text
        assert "no applicable tool" in text
        assert "resisted" in text
        assert "conditional risk" in text
    for title in ("Resisted (1)", "Not applicable (1)", "Not tested (1)"):
        assert title in html
        assert title in markdown
