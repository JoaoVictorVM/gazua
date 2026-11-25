import json

import pytest
from ci_support import plain_run, run_with_baseline

from gazua.catalog.models import DAMAGES
from gazua.ci.models import CiFinding
from gazua.ci.projection import project
from gazua.ci.sarif import (
    FINGERPRINT,
    SarifProfileError,
    build_sarif,
    sarif_json,
    validate_sarif,
)


def _sarif(run: object) -> dict:  # type: ignore[type-arg]
    return json.loads(sarif_json(build_sarif(project(run))))  # type: ignore[arg-type]


def test_findings_map_to_rules_levels_and_fingerprints() -> None:
    data = _sarif(plain_run())

    [run] = data["runs"]
    assert data["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "Gazua"
    assert {rule["id"] for rule in run["tool"]["driver"]["rules"]} == {
        f"gazua/{damage}" for damage in DAMAGES
    }
    [result] = run["results"]
    finding = plain_run().findings[0]
    assert result["ruleId"] == "gazua/idor_via_agent"
    assert result["level"] == "error"
    assert result["partialFingerprints"] == {FINGERPRINT: finding.id}
    assert result["locations"] == [
        {"physicalLocation": {"artifactLocation": {"uri": "gazua.yaml"}}}
    ]
    assert "region" not in json.dumps(result)
    assert "baselineState" not in result
    assert result["message"]["text"] == (
        f"Gazua finding {finding.id}: high idor_via_agent in get_order."
    )


@pytest.mark.parametrize(
    ("severity", "level"), [("critical", "error"), ("medium", "warning"), ("low", "note")]
)
def test_severity_levels(severity: str, level: str) -> None:
    summary = project(plain_run())
    finding = summary.findings[0].model_copy(update={"severity": severity})
    changed = summary.model_copy(update={"findings": [finding]})

    [result] = build_sarif(changed).runs[0].results

    assert result.level == level


def test_baseline_state_maps_new_and_open() -> None:
    known = _sarif(run_with_baseline("open"))["runs"][0]["results"][0]
    regressed = _sarif(run_with_baseline("closed"))["runs"][0]["results"][0]

    assert known["baselineState"] == "unchanged"
    assert regressed["baselineState"] == "new"
    assert regressed["properties"]["regression"] is True


def test_not_tested_is_not_a_result() -> None:
    data = _sarif(plain_run())

    [run] = data["runs"]
    assert len(run["results"]) == 1
    [invocation] = run["invocations"]
    assert invocation["properties"]["notTested"] == 1
    assert invocation["properties"]["notApplicable"] == 1
    codes = [item["descriptor"]["id"] for item in invocation["toolExecutionNotifications"]]
    assert codes == ["gazua_not_tested", "gazua_not_applicable"]
    assert invocation["executionSuccessful"] is True


def test_sarif_has_no_attack_conversation_or_proof() -> None:
    run = plain_run()

    text = sarif_json(build_sarif(project(run)))

    for scenario in run.scenarios:
        assert scenario.attack not in text
        assert json.dumps(scenario.payload) not in text
    for proof in run.proofs:
        assert proof.execution_id not in text
    assert run.metadata.target_ref not in text
    assert "GAZUA-CANARY" not in text
    assert "victim-1" not in text
    assert ":\\\\" not in text
    assert "/home/" not in text


def test_operational_error_is_not_successful() -> None:
    summary = project(plain_run())
    failed = summary.model_copy(update={"effective_exit_code": 2})

    [invocation] = build_sarif(failed).runs[0].invocations

    assert invocation.executionSuccessful is False
    assert "gazua_operational_error" in [
        item.descriptor.id for item in invocation.toolExecutionNotifications
    ]


def test_inconsistent_profile_is_refused() -> None:
    text = sarif_json(build_sarif(project(plain_run())))
    data = json.loads(text)
    data["runs"][0]["results"][0]["partialFingerprints"][FINGERPRINT] = "finding-" + "0" * 64

    with pytest.raises(SarifProfileError):
        validate_sarif(json.dumps(data))
    with pytest.raises(SarifProfileError):
        validate_sarif("{")


def test_result_limit_is_an_error() -> None:
    summary = project(plain_run())
    template = summary.findings[0]
    many = [
        CiFinding.model_validate({**template.model_dump(), "id": "finding-" + f"{index:064x}"})
        for index in range(10_001)
    ]
    oversized = summary.model_construct(**{**dict(summary), "findings": many})

    with pytest.raises(SarifProfileError) as caught:
        build_sarif(oversized)

    assert caught.value.code == "sarif_too_many_results"
