import json
from pathlib import Path

import jsonschema
import pytest
from report_factory import document

from gazua.reports.models import (
    build_run_json_schema,
    packaged_run_json_schema,
    render_run_json_schema,
)
from gazua.reports.storage import RunLoadError, document_json, parse_run_document

ROOT = Path(__file__).resolve().parents[2]


def test_generated_schema_matches_packaged_schema() -> None:
    assert packaged_run_json_schema().replace("\r\n", "\n") == render_run_json_schema()
    published = (ROOT / "src/gazua/schemas/run-v1.schema.json").read_text(encoding="utf-8")
    assert published.replace("\r\n", "\n") == render_run_json_schema()


def test_examples_validate_against_schema() -> None:
    schema = build_run_json_schema()
    jsonschema.Draft202012Validator.check_schema(schema)

    jsonschema.validate(json.loads(document_json(document())), schema)


def test_unknown_version_has_migration_diagnostic() -> None:
    data = json.loads(document_json(document()))
    data["schema_version"] = 2

    with pytest.raises(RunLoadError) as caught:
        parse_run_document(json.dumps(data).encode())

    assert caught.value.code == "run_schema_version_unsupported"
