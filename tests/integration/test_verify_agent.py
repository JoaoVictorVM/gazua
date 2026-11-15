from typing import Any

from verify_support import accepted, baseline_document, gazua, latest_run


def test_normal_zero_of_five_keeps_open(agent_project: Any) -> None:
    accepted(agent_project.root, "--agent", "--mold", "secret-04")
    before = (agent_project.root / "gazua-baseline.json").read_bytes()
    agent_project.behave("hardened")

    normal = gazua(agent_project.root, "run", "--agent", "--mold", "secret-04")

    assert normal.returncode == 0, normal.stdout + normal.stderr
    run = latest_run(agent_project.root)
    [result] = [item for item in run["verdicts"]["results"] if item["mold_id"] == "secret-04"]
    assert (result["successes"], result["evaluated"]) == (0, 5)
    [entry] = run["baseline"]["entries"]
    assert (entry["observed"], entry["status"]) == (False, "open")
    assert "does not mean fixed" in normal.stdout
    assert (agent_project.root / "gazua-baseline.json").read_bytes() == before


def test_verification_runs_twenty_without_legitimate_tasks(agent_project: Any) -> None:
    entry = accepted(agent_project.root, "--agent", "--mold", "secret-04")
    agent_project.behave("hardened")

    verified = gazua(agent_project.root, "verify", "secret-04", "--mode", "agent")

    assert verified.returncode == 0, verified.stdout + verified.stderr
    assert "0/20, up to ~14%: closed" in verified.stdout
    run = latest_run(agent_project.root)
    assert run["legitimate_use"] is None
    assert all(not item["request_key"].startswith("legit") for item in run["engine"]["records"])
    attack_keys = {item["attack_key"] for item in run["verdicts"]["results"]}
    assert len(attack_keys) == len(entry["scenarios"])
    assert all(":lang:en" in key for key in attack_keys)
    starts = {item["request_key"] for item in run["engine"]["records"]}
    assert len(starts) == 20 * len(entry["scenarios"])
    assert baseline_document(agent_project.root)["entries"][0]["status"] == "closed"
