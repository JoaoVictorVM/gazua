import json
from typing import Any

from action_support import accept_findings, run_action

from gazua.ci.action import finish_step


def test_clean_run_passes(tools_project: Any) -> None:
    tools_project.harden()

    outcome, outputs = run_action(tools_project.root, GAZUA_CI_MOLD="idor-01")

    assert outcome.exit_code == 0
    assert outputs.values["exit-code"] == "0"
    assert outputs.values["new-findings"] == "0"
    assert finish_step({"GAZUA_CI_EXIT_CODE": outputs.values["exit-code"]}) == 0
    summary = (tools_project.root / "step-summary.md").read_text(encoding="utf-8")
    assert "**0 new findings, 0 known" in summary


def test_new_gated_finding_fails_job(tools_project: Any) -> None:
    outcome, outputs = run_action(tools_project.root, GAZUA_CI_MOLD="idor-01")

    assert outcome.exit_code == 1
    assert outputs.values["new-findings"] == "1"
    assert outputs.values["run-json"] == ".gazua/run.json"
    assert outputs.values["sarif"] == ".gazua/ci/gazua.sarif"
    assert outputs.values["comment"] == ".gazua/ci/comment.md"
    assert outputs.values["summary"] == ".gazua/ci/summary.json"
    assert finish_step({"GAZUA_CI_EXIT_CODE": "1"}) == 1
    summary = json.loads((tools_project.root / ".gazua/ci/summary.json").read_text("utf-8"))
    assert summary["effective_exit_code"] == 1


def test_known_finding_passes(tools_project: Any) -> None:
    accept_findings(tools_project.root)

    outcome, outputs = run_action(tools_project.root, GAZUA_CI_MOLD="idor-01")

    assert outcome.exit_code == 0
    assert (outputs.values["new-findings"], outputs.values["known-findings"]) == ("0", "1")
    comment = (tools_project.root / ".gazua/ci/comment.md").read_text(encoding="utf-8")
    assert "**0 new findings, 1 known" in comment


def test_operational_error_returns_two(tools_project: Any) -> None:
    tools_project.write(target={"reset": "tools_target:reset"})
    (tools_project.root / "reset_fail").write_text("x", encoding="utf-8")

    outcome, outputs = run_action(tools_project.root, GAZUA_CI_MOLD="idor-01")

    assert outcome.exit_code == 2
    assert outputs.values["exit-code"] == "2"
    assert finish_step({"GAZUA_CI_EXIT_CODE": "2"}) == 2
    summary = (tools_project.root / "step-summary.md").read_text(encoding="utf-8")
    assert "operational error" in summary


def test_invalid_configuration_produces_no_run(tools_project: Any) -> None:
    (tools_project.root / "gazua.yaml").write_text("schema_version: 99\n", encoding="utf-8")

    outcome, outputs = run_action(tools_project.root)

    assert outcome.exit_code == 2
    assert "ci_run_missing" in outcome.codes
    assert "sarif" not in outputs.values
    assert "comment" not in outputs.values


def test_auxiliary_upload_failure_preserves_gate(capsys: Any) -> None:
    for gate in ("0", "1"):
        failed = finish_step(
            {
                "GAZUA_CI_EXIT_CODE": gate,
                "GAZUA_CI_UPLOAD_SARIF": "true",
                "GAZUA_CI_SARIF_PATH": ".gazua/ci/gazua.sarif",
                "GAZUA_CI_SARIF_OUTCOME": "failure",
            }
        )
        assert failed == int(gate)
    assert "ci_sarif_upload_failed" in capsys.readouterr().out
    assert finish_step({"GAZUA_CI_EXIT_CODE": "nonsense"}) == 2
