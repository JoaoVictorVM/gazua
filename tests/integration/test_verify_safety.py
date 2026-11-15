from typing import Any

from verify_support import accepted, baseline_document, gazua, latest_run


def test_reset_dry_run_receiver_and_budget_are_preserved(tools_project: Any) -> None:
    tools_project.write(target={"reset": "tools_target:reset"})
    accepted(tools_project.root, "--tools", "--mold", "idor-01")
    tools_project.harden()
    tools_project.clear_effects()

    verified = gazua(tools_project.root, "verify", "idor-01", "--max-runs", "20")

    assert verified.returncode == 0, verified.stdout + verified.stderr
    effects = tools_project.effects()
    kinds = [item["kind"] for item in effects]
    assert "reset" in kinds
    assert kinds.count("get_order") == 20
    for unreleased in ("delete_account", "send_email", "entrypoint_called", "network"):
        assert unreleased not in kinds
    assert "credential_read" not in kinds
    run = latest_run(tools_project.root)
    assert run["engine"]["limits"]["max_runs"] == 20
    assert run["engine"]["started"] == 20
    assert run["engine"]["cleanup"] == "succeeded"
    assert "20 executions" in verified.stdout


def test_insufficient_budget_runs_no_attack(tools_project: Any) -> None:
    accepted(tools_project.root, "--tools", "--mold", "idor-01")
    before = baseline_document(tools_project.root)
    archived = sorted((tools_project.root / ".gazua" / "runs").iterdir())
    tools_project.clear_effects()

    refused = gazua(tools_project.root, "verify", "idor-01", "--max-runs", "19")

    assert refused.returncode == 2
    assert "verification_insufficient_budget" in refused.stderr
    assert not [item for item in tools_project.effects() if item["kind"] == "get_order"]
    assert baseline_document(tools_project.root) == before
    assert sorted((tools_project.root / ".gazua" / "runs").iterdir()) == archived

    unknown = gazua(tools_project.root, "verify", "idor-09")
    assert unknown.returncode == 2
    assert "verification_finding_unknown" in unknown.stderr
