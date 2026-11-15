import json
from typing import Any

import jsonschema
import pytest
from verify_support import accepted, gazua, latest_run

from gazua.baseline.models import BaselineComparison, baseline_json, build_baseline_json_schema
from gazua.baseline.storage import BaselineError, parse_baseline
from gazua.reports.storage import load_run_document


def test_ci_consumer_gets_status_and_effective_gate_without_attack_text(
    tools_project: Any,
) -> None:
    accepted(tools_project.root, "--tools", "--mold", "idor-01")
    tools_project.cli("--tools")

    document = load_run_document(tools_project.root / ".gazua" / "run.json")

    comparison = document.baseline
    assert isinstance(comparison, BaselineComparison)
    projection = comparison.model_dump(mode="json")
    text = json.dumps(projection)
    for scenario in document.scenarios:
        assert scenario.attack not in text
    for snapshot in document.proofs:
        assert snapshot.execution_id not in text
    observed = [item for item in projection["entries"] if item["observed"]]
    assert {item["finding_id"] for item in observed} == {item.id for item in document.findings}
    gated_new = [item["finding_id"] for item in observed if item["effective_gated"]]
    assert comparison.has_new_gated_findings == bool(gated_new)
    assert document.report_exit_code == (1 if gated_new else 0)
    assert document.verdicts.has_gated_findings
    assert set(projection) == {
        "schema_version",
        "baseline_revision",
        "baseline_digest",
        "observed_known",
        "observed_new",
        "has_new_gated_findings",
        "entries",
    }
    assert "sarif" not in latest_run(tools_project.root)


def test_versioned_baseline_roundtrip_and_unknown_version_rejection(tools_project: Any) -> None:
    accepted(tools_project.root, "--tools", "--mold", "idor-01")
    path = tools_project.root / "gazua-baseline.json"
    content = path.read_bytes()

    parsed = parse_baseline(content)

    assert baseline_json(parsed).encode("utf-8") == content.replace(b"\r\n", b"\n")
    jsonschema.validate(json.loads(content), build_baseline_json_schema())
    future = json.loads(content)
    future["schema_version"] = 2
    with pytest.raises(BaselineError) as caught:
        parse_baseline(json.dumps(future).encode())
    assert caught.value.code == "baseline_version_unsupported"
    path.write_text(json.dumps(future), encoding="utf-8")
    refused = gazua(tools_project.root, "run", "--tools", "--mold", "idor-01")
    assert refused.returncode == 2
    assert "baseline_version_unsupported" in refused.stderr
    assert "migration" in refused.stderr
