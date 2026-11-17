import json
from typing import Any

import jsonschema
import pytest
from benchmarks.selftest.models import (
    SCHEMA_FILE,
    BenchmarkSummary,
    CellResult,
    build_benchmark_json_schema,
    count_cells,
    render_benchmark_json_schema,
)

DIGEST = "a" * 64


def cell(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "case_id": "idor-01-tools-python-hardened",
        "kind": "target",
        "mold_id": "idor-01",
        "mode": "tools",
        "language": "en",
        "framework": "python",
        "variant": "hardened",
        "fixture_id": "victim-records",
        "disabled_control": None,
        "outcome": "passed",
        "negative": True,
        "observed_states": {"get_order#0#-": "resisted"},
        "run_document": "runs/python-hardened-en/run.json",
    }
    document.update(overrides)
    return document


def summary(cells: list[dict[str, Any]], **overrides: Any) -> dict[str, Any]:
    parsed = [CellResult.model_validate(item) for item in cells]
    document: dict[str, Any] = {
        "schema_version": 1,
        "profile": "release",
        "status": "passed",
        "scope": "selection",
        "simulated": True,
        "catalog_release": "v0.1",
        "provenance": {
            "commit": "0" * 40,
            "dirty": False,
            "gazua_version": "0.1.0.dev0",
            "matrix_revision": "example",
            "matrix_digest": DIGEST,
            "catalog_digest": DIGEST,
            "runtime": "python",
        },
        "counts": count_cells(parsed).model_dump(),
        "cells": cells,
        "artifacts": ["summary.md"],
    }
    document.update(overrides)
    return document


def test_counts_equal_cells() -> None:
    valid = summary([cell()])
    parsed = BenchmarkSummary.model_validate(valid)
    assert parsed.counts.expected_cells == 1
    assert parsed.counts.negative_expected == 1
    assert parsed.counts.false_alarm_cells == 0

    inflated = json.loads(json.dumps(valid))
    inflated["counts"]["passed_cells"] = 2
    with pytest.raises(ValueError, match="counts do not match"):
        BenchmarkSummary.model_validate(inflated)

    failed = summary([cell(outcome="failed")])
    with pytest.raises(ValueError, match="a passed result"):
        BenchmarkSummary.model_validate(failed)
    BenchmarkSummary.model_validate({**failed, "status": "failed"})

    with pytest.raises(ValueError, match="pending cell needs"):
        CellResult.model_validate(cell(outcome="pending", run_document=None))
    with pytest.raises(ValueError, match="needs its run document"):
        CellResult.model_validate(cell(run_document=None))


def test_unknown_version_rejected() -> None:
    with pytest.raises(ValueError, match="schema_version"):
        BenchmarkSummary.model_validate({**summary([cell()]), "schema_version": 2})
    with pytest.raises(ValueError, match="never simulated"):
        BenchmarkSummary.model_validate({**summary([cell()]), "profile": "real"})
    with pytest.raises(ValueError, match="every release"):
        BenchmarkSummary.model_validate({**summary([cell()]), "scope": "full"})


@pytest.mark.parametrize(
    "path", ["/etc/passwd", "../outside.json", "C:/run.json", "runs\\run.json", "a/../../b"]
)
def test_relative_artifacts_cannot_escape(path: str) -> None:
    with pytest.raises(ValueError, match="inside the benchmark folder"):
        BenchmarkSummary.model_validate(summary([cell()], artifacts=[path]))
    with pytest.raises(ValueError, match="inside the benchmark folder"):
        CellResult.model_validate(cell(run_document=path))


def test_schema_matches_models() -> None:
    assert SCHEMA_FILE.read_text(encoding="utf-8") == render_benchmark_json_schema()
    schema = build_benchmark_json_schema()
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(summary([cell()]), schema)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({**summary([cell()]), "simulated": "yes"}, schema)


def test_partial_or_unproven_result_is_not_full_evidence() -> None:
    selection = BenchmarkSummary.model_validate(summary([cell()]))
    assert selection.scope != "full"
    assert selection.status == "passed"
    with pytest.raises(ValueError, match="needs a reason"):
        BenchmarkSummary.model_validate(
            summary([cell()], provenance={**summary([cell()])["provenance"], "commit": None})
        )
