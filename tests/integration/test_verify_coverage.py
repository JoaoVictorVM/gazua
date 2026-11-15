import json
from typing import Any

from verify_support import accepted, baseline_document, gazua, latest_run

SECOND_RECORD = {"tool": "get_order", "id_arg": "order_id", "id": "order-victim-2"}


def test_multiple_scenarios_need_twenty_each(tools_project: Any) -> None:
    document = tools_project.document()
    document["fixtures"]["victim"]["records"].append(SECOND_RECORD)
    tools_project.write(fixtures=document["fixtures"])
    gazua(tools_project.root, "run", "--tools", "--mold", "idor-01")
    gazua(tools_project.root, "baseline")
    gazua(tools_project.root, "run", "--tools", "--mold", "idor-01", "--language", "pt")
    gazua(tools_project.root, "baseline")
    [entry] = baseline_document(tools_project.root)["entries"]
    assert {item["language"] for item in entry["scenarios"]} == {"en", "pt"}
    assert len(entry["scenarios"]) == 4
    tools_project.harden()

    short = gazua(tools_project.root, "verify", "idor-01", "--max-runs", "79")
    assert short.returncode == 2
    assert "verification_insufficient_budget" in short.stderr

    verified = gazua(tools_project.root, "verify", "idor-01")

    assert verified.returncode == 0, verified.stdout + verified.stderr
    samples = latest_run(tools_project.root)["verification"]["samples"]
    assert len(samples) == 4
    assert len({item["attack_key"] for item in samples}) == 4
    assert all(item["evaluated"] == 20 and item["successes"] == 0 for item in samples)
    assert {item["language"] for item in samples} == {"en", "pt"}
    assert "Each scenario has its own rate" in verified.stdout
    assert baseline_document(tools_project.root)["entries"][0]["status"] == "closed"


def test_changed_fixture_and_missing_tool_do_not_close(tools_project: Any) -> None:
    accepted(tools_project.root, "--tools", "--mold", "idor-01")
    before = (tools_project.root / "gazua-baseline.json").read_bytes()
    tools_project.harden()
    tools_project.clear_effects()
    document = tools_project.document()
    document["fixtures"]["victim"]["records"][0]["id"] = "order-victim-renamed"
    tools_project.write(fixtures=document["fixtures"])

    changed = gazua(tools_project.root, "verify", "idor-01")

    assert changed.returncode == 2
    assert "verification_coverage_changed" in changed.stderr or (
        "verification_finding_unknown" in changed.stderr
    )
    assert not [item for item in tools_project.effects() if item["kind"] == "get_order"]

    tools_project.write()
    tools = json.loads(json.dumps(tools_project.document()["tools"]))
    tools["get_order"]["safe"] = False
    tools_project.write(tools=tools)

    unsafe = gazua(tools_project.root, "verify", "idor-01")

    assert unsafe.returncode == 2
    assert "verification_coverage_changed" in unsafe.stderr
    assert not [item for item in tools_project.effects() if item["kind"] == "get_order"]
    assert (tools_project.root / "gazua-baseline.json").read_bytes() == before
