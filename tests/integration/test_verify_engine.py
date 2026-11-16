from typing import Any

from verify_support import accepted, baseline_document, gazua, latest_run

from gazua.baseline.models import original_key, scenario_digest


def test_verify_uses_native_records_verdicts_and_findings(tools_project: Any) -> None:
    entry = accepted(tools_project.root, "--tools", "--mold", "idor-01")

    still = gazua(tools_project.root, "verify", entry["id"])

    assert still.returncode == 1, still.stdout + still.stderr
    run = latest_run(tools_project.root)
    [finding] = run["findings"]
    assert finding["id"] == entry["id"]
    records = {item["execution_id"]: item for item in run["engine"]["records"]}
    results = {item["attack_key"]: item for item in run["verdicts"]["results"]}
    for sample in run["verification"]["samples"]:
        native = results[sample["attack_key"]]
        assert (sample["successes"], sample["evaluated"], sample["upper_bound"]) == (
            native["successes"],
            native["evaluated"],
            native["upper_bound"],
        )
        assert native["proof"]
        for proof in native["proof"]:
            assert records[proof["execution_id"]]["request_key"].startswith(sample["attack_key"])
        split = original_key(sample["attack_key"])
        assert split is not None
        assert scenario_digest(split[0]) == sample["scenario_digest"]
        assert {"scenario_digest": sample["scenario_digest"], "language": "en"} in entry[
            "scenarios"
        ]
    attempts = {item["request_key"] for item in run["engine"]["records"]}
    assert len(attempts) == 20 * len(entry["scenarios"])

    tools_project.harden()
    closed = gazua(tools_project.root, "verify", entry["id"])

    assert closed.returncode == 0, closed.stdout + closed.stderr
    receipt = baseline_document(tools_project.root)["entries"][0]["verification"]
    assert receipt["run_id"] == latest_run(tools_project.root)["run_id"]
    assert (tools_project.root / ".gazua" / "runs" / receipt["run_id"] / "run.json").exists()
