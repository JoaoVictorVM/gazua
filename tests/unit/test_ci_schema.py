import json
import subprocess
import sys

import jsonschema
import pytest
from ci_support import FIXTURES, ROOT, SARIF_SCHEMA, plain_run, run_with_baseline

from gazua.ci.models import (
    CI_SUMMARY_SCHEMA_FILE,
    PR_COMMENT_SCHEMA_FILE,
    SARIF_PROFILE_SCHEMA_FILE,
    CiSummary,
    CommentDocument,
    build_ci_summary_schema,
    build_pr_comment_schema,
    packaged_schema,
    render_schema,
)
from gazua.ci.projection import comment_document, project
from gazua.ci.sarif import build_sarif, build_sarif_profile_schema, sarif_json, validate_sarif

GENERATED = {
    CI_SUMMARY_SCHEMA_FILE: build_ci_summary_schema,
    PR_COMMENT_SCHEMA_FILE: build_pr_comment_schema,
    SARIF_PROFILE_SCHEMA_FILE: build_sarif_profile_schema,
}


@pytest.mark.parametrize("name", sorted(GENERATED))
def test_ci_schemas_match_generators(name: str) -> None:
    expected = render_schema(GENERATED[name]())

    assert packaged_schema(name).replace("\r\n", "\n") == expected
    published = (ROOT / "src/gazua/schemas" / name).read_text(encoding="utf-8")
    assert published.replace("\r\n", "\n") == expected
    jsonschema.Draft202012Validator.check_schema(json.loads(expected))


def test_generator_check_mode_is_clean() -> None:
    completed = subprocess.run(
        [sys.executable, str(ROOT / ".github/scripts/generate_ci_schemas.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout


@pytest.mark.parametrize("status", [None, "open", "closed"])
def test_sarif_profile_validates_official_210_schema(status: str | None) -> None:
    run = plain_run() if status is None else run_with_baseline(status)
    data = json.loads(sarif_json(build_sarif(project(run))))
    official = json.loads(SARIF_SCHEMA.read_text(encoding="utf-8"))

    jsonschema.Draft4Validator(official).validate(data)
    jsonschema.validate(data, build_sarif_profile_schema())


def test_v1_fixtures_remain_valid() -> None:
    summary = json.loads((FIXTURES / "ci-summary-v1.json").read_text(encoding="utf-8"))
    comment = json.loads((FIXTURES / "pr-comment-v1.json").read_text(encoding="utf-8"))
    sarif_text = (FIXTURES / "gazua-sarif-v1.sarif").read_text(encoding="utf-8")
    official = json.loads(SARIF_SCHEMA.read_text(encoding="utf-8"))

    jsonschema.validate(summary, json.loads(packaged_schema(CI_SUMMARY_SCHEMA_FILE)))
    jsonschema.validate(comment, json.loads(packaged_schema(PR_COMMENT_SCHEMA_FILE)))
    jsonschema.validate(
        json.loads(sarif_text), json.loads(packaged_schema(SARIF_PROFILE_SCHEMA_FILE))
    )
    jsonschema.Draft4Validator(official).validate(json.loads(sarif_text))
    CiSummary.model_validate(summary, strict=False)
    CommentDocument.model_validate(comment, strict=False)
    validate_sarif(sarif_text)


def test_v1_fixtures_still_match_the_producer() -> None:
    summary = project(run_with_baseline("closed"))

    produced = json.loads(sarif_json(build_sarif(summary)))
    fixture = json.loads((FIXTURES / "gazua-sarif-v1.sarif").read_text(encoding="utf-8"))
    for item in (produced, fixture):
        item["runs"][0]["tool"]["driver"].pop("semanticVersion", None)
    assert produced == fixture
    assert json.loads(comment_document(summary).model_dump_json()) == json.loads(
        (FIXTURES / "pr-comment-v1.json").read_text(encoding="utf-8")
    )
