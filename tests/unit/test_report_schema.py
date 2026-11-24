import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from baseline_factory import baseline
from baseline_factory import entry as baseline_entry
from pydantic import ValidationError
from report_factory import document

from gazua.baseline.models import scenario_digest
from gazua.reports.legacy import (
    build_run_v1_json_schema,
    packaged_run_v1_json_schema,
    render_run_v1_json_schema,
)
from gazua.reports.legacy_v2 import (
    build_run_v2_json_schema,
    packaged_run_v2_json_schema,
    render_run_v2_json_schema,
)
from gazua.reports.legacy_v4 import (
    packaged_run_v4_json_schema,
    render_run_v4_json_schema,
)
from gazua.reports.models import (
    RunDocument,
    build_run_json_schema,
    packaged_run_json_schema,
    render_run_json_schema,
)
from gazua.reports.rendering import render_report
from gazua.reports.storage import RunLoadError, document_json, parse_run_document

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "tests" / "support" / "run-example.json"
EXAMPLE_V2 = ROOT / "tests" / "support" / "run-example-v2.json"


def test_v6_schema_matches_generator() -> None:
    assert packaged_run_json_schema().replace("\r\n", "\n") == render_run_json_schema()
    published = (ROOT / "src/gazua/schemas/run-v6.schema.json").read_text(encoding="utf-8")
    assert published.replace("\r\n", "\n") == render_run_json_schema()
    assert "guide" in build_run_json_schema()["required"]
    assert "http" in build_run_json_schema()["required"]
    assert "typescript" in build_run_json_schema()["required"]


def test_v4_schema_is_frozen() -> None:
    published = (ROOT / "src/gazua/schemas/run-v4.schema.json").read_text(encoding="utf-8")
    assert packaged_run_v4_json_schema().replace("\r\n", "\n") == render_run_v4_json_schema()
    assert published.replace("\r\n", "\n") == render_run_v4_json_schema()


@pytest.mark.parametrize(
    ("packaged", "rendered", "built", "name", "example"),
    [
        (
            packaged_run_v1_json_schema,
            render_run_v1_json_schema,
            build_run_v1_json_schema,
            "run-v1.schema.json",
            EXAMPLE,
        ),
        (
            packaged_run_v2_json_schema,
            render_run_v2_json_schema,
            build_run_v2_json_schema,
            "run-v2.schema.json",
            EXAMPLE_V2,
        ),
    ],
)
def test_legacy_schemas_are_preserved(
    packaged: Any, rendered: Any, built: Any, name: str, example: Path
) -> None:
    assert packaged().replace("\r\n", "\n") == rendered()
    published = (ROOT / "src/gazua/schemas" / name).read_text(encoding="utf-8")
    assert published.replace("\r\n", "\n") == rendered()
    schema = built()
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(json.loads(example.read_text(encoding="utf-8")), schema)
    assert "guide" not in schema["properties"]


def test_examples_validate_against_schema() -> None:
    schema = build_run_json_schema()
    jsonschema.Draft202012Validator.check_schema(schema)

    jsonschema.validate(json.loads(document_json(document())), schema)


def test_v1_adapts_without_baseline() -> None:
    content = EXAMPLE.read_bytes()
    original = json.loads(content)

    adapted = parse_run_document(content)

    assert original["schema_version"] == 1
    assert adapted.schema_version == 6
    assert adapted.target_adapter == "python"
    assert adapted.http is None
    assert adapted.guide.origin == "legacy_fallback"
    assert adapted.baseline is None
    assert adapted.verification is None
    assert [item.attack_key for item in adapted.scenarios] == [
        item["attack_key"] for item in original["scenarios"]
    ]
    for scenario in adapted.scenarios:
        assert scenario.baseline_reference.scenario_digest == scenario_digest(scenario.attack_key)
        assert scenario.baseline_reference.language == original["metadata"]["language"]
    assert adapted.report_exit_code == original["report_exit_code"]
    assert EXAMPLE.read_bytes() == content
    html, markdown = render_report(adapted)
    assert "Baseline comparison" not in markdown
    assert "Verification" not in html


def test_v2_snapshot_invariants() -> None:
    built = document()
    [finding] = built.findings
    known = baseline(baseline_entry(finding.id))

    compared = document(baseline=known)

    assert compared.baseline is not None
    assert compared.baseline.observed_known == 1
    assert compared.report_exit_code == 0
    assert compared.verdicts.has_gated_findings
    assert compared.findings == built.findings
    assert [item.id for item in compared.proofs] == [item.id for item in built.proofs]
    data = json.loads(document_json(compared))
    data["report_exit_code"] = 1
    with pytest.raises(ValidationError):
        RunDocument.model_validate_json(json.dumps(data))
    data = json.loads(document_json(compared))
    data["baseline"]["entries"][0]["native_gated"] = False
    data["baseline"]["entries"][0]["effective_gated"] = False
    with pytest.raises(ValidationError):
        RunDocument.model_validate_json(json.dumps(data))
    data = json.loads(document_json(compared))
    data["baseline"]["entries"].clear()
    with pytest.raises(ValidationError):
        RunDocument.model_validate_json(json.dumps(data))


def test_unknown_version_has_migration_diagnostic() -> None:
    data = json.loads(document_json(document()))
    data["schema_version"] = 7

    with pytest.raises(RunLoadError) as caught:
        parse_run_document(json.dumps(data).encode())

    assert caught.value.code == "run_schema_version_unsupported"

    data["schema_version"] = True
    with pytest.raises(RunLoadError) as boolean:
        parse_run_document(json.dumps(data).encode())
    assert boolean.value.code == "run_schema_version_unsupported"
