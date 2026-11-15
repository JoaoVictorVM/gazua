from typing import Any

from verify_support import accepted, baseline_document, gazua, latest_run


def test_fix_closes_only_after_twenty(tools_project: Any) -> None:
    entry = accepted(tools_project.root, "--tools", "--mold", "idor-01")
    tools_project.harden()
    tools_project.clear_effects()

    verified = gazua(tools_project.root, "verify", "idor-01", "--mode", "tools")

    assert verified.returncode == 0, verified.stdout + verified.stderr
    assert "0/20, up to ~14%: closed" in verified.stdout
    assert "closure eligible at verification time" in verified.stdout
    calls = [item for item in tools_project.effects() if item["kind"] == "get_order"]
    assert len(calls) == 20 * len(entry["scenarios"])
    [closed] = baseline_document(tools_project.root)["entries"]
    assert closed["status"] == "closed"
    run = latest_run(tools_project.root)
    receipt = closed["verification"]
    assert receipt["run_id"] == run["run_id"]
    assert receipt["repetitions"] == 20
    assert receipt["scenarios"] == closed["scenarios"]
    assert run["verification"]["outcome"] == "verified"
    assert run["report_exit_code"] == 0
    [sample] = run["verification"]["samples"]
    assert (sample["planned"], sample["evaluated"], sample["successes"]) == (20, 20, 0)
    assert abs(sample["upper_bound"] - 0.1391) < 1e-3

    normal = tools_project.cli("--tools", "--mold", "idor-01")
    assert normal.returncode == 0
    assert baseline_document(tools_project.root)["entries"][0]["status"] == "closed"


def test_success_remains_open(tools_project: Any) -> None:
    accepted(tools_project.root, "--tools", "--mold", "idor-01")
    before = (tools_project.root / "gazua-baseline.json").read_bytes()

    still = gazua(tools_project.root, "verify", "idor-01")

    assert still.returncode == 1, still.stdout + still.stderr
    assert "20/20, up to ~100%: open" in still.stdout
    assert (tools_project.root / "gazua-baseline.json").read_bytes() == before
    run = latest_run(tools_project.root)
    assert run["verification"]["outcome"] == "still_open"
    assert run["verification"]["proposed_status"] == "open"
    assert run["findings"]
