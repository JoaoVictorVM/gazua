import json
from typing import Any

import jsonschema
from action_support import accept_findings, run_action
from ci_support import SARIF_SCHEMA

from gazua.ci.action import finish_step
from gazua.reports.storage import load_run_document

ALLOWED = {"findingId", "severity", "damage", "mode", "tool", "regression", "reproduction"}


def _sarif(root: Any, path: str) -> dict[str, Any]:
    return json.loads((root / path).read_text(encoding="utf-8"))


def test_tools_findings_and_baseline_produce_expected_sarif(tools_project: Any) -> None:
    accept_findings(tools_project.root)
    _, known = run_action(tools_project.root, GAZUA_CI_MOLD="idor-01")
    known_sarif = _sarif(tools_project.root, known.values["sarif"])
    _, plain = run_action(tools_project.root, GAZUA_CI_MOLD="idor-01", GAZUA_CI_BASELINE="")

    run = load_run_document(tools_project.root / ".gazua" / "run.json")
    [finding] = run.findings
    [result] = known_sarif["runs"][0]["results"]
    assert result["baselineState"] == "unchanged"
    assert result["partialFingerprints"]["gazuaFindingId/v1"] == finding.id
    assert result["level"] == "error"
    assert known_sarif["runs"][0]["invocations"][0]["properties"]["knownFindings"] == 1
    official = json.loads(SARIF_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft4Validator(official).validate(known_sarif)
    assert plain.values["sarif"] == ".gazua/ci/gazua.sarif"


def test_code_scanning_projection_contains_allowed_fields_only(tools_project: Any) -> None:
    _, outputs = run_action(tools_project.root)

    data = _sarif(tools_project.root, outputs.values["sarif"])

    run = load_run_document(tools_project.root / ".gazua" / "run.json")
    text = json.dumps(data)
    assert data["runs"][0]["results"]
    for result in data["runs"][0]["results"]:
        assert set(result) <= {
            "ruleId",
            "level",
            "message",
            "baselineState",
            "partialFingerprints",
            "locations",
            "properties",
        }
        assert set(result["properties"]) <= ALLOWED
    for scenario in run.scenarios:
        assert scenario.attack not in text
    assert "GAZUA-CANARY-7f3a9c" not in text
    assert str(tools_project.root) not in text


def test_upload_failure_keeps_gate(tools_project: Any) -> None:
    _, outputs = run_action(tools_project.root, GAZUA_CI_MOLD="idor-01")

    code = finish_step(
        {
            "GAZUA_CI_EXIT_CODE": outputs.values["exit-code"],
            "GAZUA_CI_UPLOAD_SARIF": "true",
            "GAZUA_CI_SARIF_PATH": outputs.values["sarif"],
            "GAZUA_CI_SARIF_OUTCOME": "failure",
        }
    )

    assert code == 1
    assert (tools_project.root / outputs.values["sarif"]).is_file()


def test_profile_category_is_stable(tools_project: Any) -> None:
    tools_project.harden()

    _, first = run_action(tools_project.root, GAZUA_CI_MOLD="idor-01")
    _, second = run_action(tools_project.root, GAZUA_CI_MOLD="idor-01")

    assert first.values["sarif-category"] == second.values["sarif-category"] == "gazua/tools"
    assert first.values["sarif"] == second.values["sarif"]
