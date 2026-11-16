import json
import sys
from typing import Any

from conftest import run_process


def gazua(project: Any, *arguments: str) -> Any:
    return run_process([sys.executable, "-m", "gazua", *arguments], cwd=project.root)


def latest(project: Any) -> dict[str, Any]:
    return json.loads((project.root / ".gazua" / "run.json").read_text(encoding="utf-8"))


def test_known_passes_new_high_and_critical_fail(tools_project: Any) -> None:
    first = tools_project.cli("--tools", "--mold", "idor-01")
    assert first.returncode == 1, first.stderr
    assert gazua(tools_project, "baseline").returncode == 0
    baseline_bytes = (tools_project.root / "gazua-baseline.json").read_bytes()

    known = tools_project.cli("--tools", "--mold", "idor-01")

    assert known.returncode == 0, known.stdout + known.stderr
    assert "1 known finding, 0 new" in known.stdout
    assert "known, accepted as open" in known.stdout
    document = latest(tools_project)
    assert document["schema_version"] == 2
    assert document["verdicts"]["has_gated_findings"] is True
    assert document["findings"][0]["gated"] is True
    assert document["proofs"]
    assert document["baseline"]["observed_known"] == 1
    assert document["report_exit_code"] == 0

    everything = tools_project.cli("--tools")

    assert everything.returncode == 1, everything.stdout + everything.stderr
    document = latest(tools_project)
    comparison = document["baseline"]
    severities = {item["id"]: item["severity"] for item in document["findings"]}
    new_gated = [item for item in comparison["entries"] if item["effective_gated"]]
    assert new_gated
    assert {severities[item["finding_id"]] for item in new_gated} <= {"high", "critical"}
    assert comparison["observed_known"] == 1
    assert (tools_project.root / "gazua-baseline.json").read_bytes() == baseline_bytes

    ignored = tools_project.cli("--tools", "--mold", "idor-01", "--no-baseline")
    assert ignored.returncode == 1
    assert latest(tools_project)["baseline"] is None


def test_closed_finding_recurrence_fails_again(tools_project: Any) -> None:
    tools_project.cli("--tools", "--mold", "idor-01")
    gazua(tools_project, "baseline")
    path = tools_project.root / "gazua-baseline.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    [entry] = document["entries"]
    entry["status"] = "closed"
    entry["verification"] = {
        "run_id": "GAZUA-run-earlier",
        "verified_at": "2026-01-02T00:00:00Z",
        "repetitions": 20,
        "scenarios": entry["scenarios"],
    }
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    content = path.read_bytes()

    again = tools_project.cli("--tools", "--mold", "idor-01")

    assert again.returncode == 1, again.stdout + again.stderr
    assert "closed before and found again" in again.stdout
    [compared] = latest(tools_project)["baseline"]["entries"]
    assert (compared["baseline_status"], compared["status"], compared["regression"]) == (
        "closed",
        "new",
        True,
    )
    assert compared["effective_gated"] is True
    assert path.read_bytes() == content

    still = tools_project.cli("--tools", "--mold", "idor-01")
    assert still.returncode == 1
    assert path.read_bytes() == content
