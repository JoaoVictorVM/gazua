import json
from pathlib import Path

import jsonschema
import pytest
from baseline_factory import FINDING_B, baseline_bytes, document_data, entry

from gazua.baseline.models import (
    build_baseline_json_schema,
    packaged_baseline_json_schema,
    render_baseline_json_schema,
)
from gazua.baseline.storage import MESSAGES, BaselineError, parse_baseline

ROOT = Path(__file__).resolve().parents[2]


def test_generated_schema_matches_packaged_schema() -> None:
    assert packaged_baseline_json_schema().replace("\r\n", "\n") == render_baseline_json_schema()
    published = (ROOT / "src/gazua/schemas/baseline-v1.schema.json").read_text(encoding="utf-8")
    assert published.replace("\r\n", "\n") == render_baseline_json_schema()


def test_examples_validate_against_schema() -> None:
    schema = build_baseline_json_schema()
    jsonschema.Draft202012Validator.check_schema(schema)

    jsonschema.validate(
        json.loads(baseline_bytes(entry(), entry(FINDING_B, status="closed"))), schema
    )


def test_reads_other_package_version_with_same_schema() -> None:
    data = document_data(entry())
    data["gazua_version"] = "9.4.1"

    parsed = parse_baseline(json.dumps(data).encode())

    assert parsed.gazua_version == "9.4.1"
    assert parsed.entries[0].status == "open"


def test_unknown_schema_has_migration_message() -> None:
    data = document_data(entry())
    data["schema_version"] = 2

    with pytest.raises(BaselineError) as caught:
        parse_baseline(json.dumps(data).encode())

    assert caught.value.code == "baseline_version_unsupported"
    assert "migration" in MESSAGES["baseline_version_unsupported"]
