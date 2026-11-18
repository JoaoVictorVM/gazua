from typing import Any

import pytest
from benchmarks.selftest.models import BenchmarkSummary, CellResult, count_cells
from benchmarks.selftest.publishing import (
    END,
    START,
    check,
    main,
    publish,
    readme_block,
    summary_markdown,
)

KEY = {"mode": "tools", "mold_id": "idor-01", "tool": "get_order", "signal": "victim_record_access"}
README = f"# Project\n\nIntro.\n\n{START}\nNot published yet.\n{END}\n\n## Next\n"


def summary(scope: str = "release", status: str = "passed", **extra: Any) -> BenchmarkSummary:
    cells = [
        CellResult.model_validate(
            {
                "case_id": "idor-01-tools-python-vulnerable",
                "kind": "target",
                "mold_id": "idor-01",
                "mode": "tools",
                "language": "en",
                "framework": "python",
                "variant": "vulnerable",
                "fixture_id": "victim-records",
                "disabled_control": None,
                "outcome": "passed" if status == "passed" else "failed",
                "positive": True,
                "expected_findings": [KEY],
                "observed_findings": [KEY],
                "finding_ids": ["finding-" + "a" * 64],
                "run_document": "runs/x/run.json",
            }
        )
    ]
    return BenchmarkSummary.model_validate(
        {
            "schema_version": 1,
            "profile": "release",
            "status": status,
            "scope": scope,
            "simulated": True,
            "catalog_release": "v0.1",
            "provenance": {
                "commit": "0123456789abcdef0123456789abcdef01234567",
                "dirty": False,
                "gazua_version": "0.1.0.dev0",
                "matrix_revision": "r1",
                "matrix_digest": "b" * 64,
                "catalog_digest": "c" * 64,
                "runtime": "CPython 3.11",
            },
            "counts": count_cells(cells).model_dump(),
            "cells": [item.model_dump() for item in cells],
            "artifacts": [],
            **extra,
        }
    )


def test_table_derives_from_the_result_without_private_data() -> None:
    block = readme_block(summary())
    assert block.startswith(START)
    assert block.endswith(END)
    assert "100.0% (1/1)" in block
    assert "0123456789ab" in block
    assert "finding-" not in block
    assert "runs/x" not in block
    assert "not applicable" in block


def test_manual_edit_is_detected() -> None:
    published = publish(README, summary())
    assert check(published, summary()) == []
    edited = published.replace("100.0% (1/1)", "100.0% (9/9)", 1)
    assert check(edited, summary()) == [
        "the README numbers differ from this result; publish it again"
    ]
    assert check("# no markers", summary()) == ["the README has no benchmark section"]
    # Provenance of a later run differs; only the numbers must match.
    later = summary().model_copy(
        update={"provenance": summary().provenance.model_copy(update={"commit": "f" * 40})}
    )
    assert check(published, later) == []


def test_selection_and_failed_release_are_not_published() -> None:
    with pytest.raises(ValueError, match="selection"):
        readme_block(summary(scope="selection"))
    assert "this release result did not pass" in check(
        publish(README, summary(status="failed")), summary(status="failed")
    )


def test_summary_markdown_lists_failures_and_gaps() -> None:
    text = summary_markdown(summary(status="failed", gaps=["anthropic: adapter"]))
    assert "Status: **failed**" in text
    assert "`idor-01-tools-python-vulnerable`" in text
    assert "anthropic: adapter" in text
    assert "finding-" not in text


def test_command_writes_and_checks(tmp_path: Any) -> None:
    source = tmp_path / "benchmark.json"
    source.write_text(summary().model_dump_json(), encoding="utf-8")
    readme = tmp_path / "README.md"
    readme.write_text(README, encoding="utf-8")

    assert main(["--from", str(source), "--readme", str(readme), "--check"]) == 1
    assert main(["--from", str(source), "--readme", str(readme)]) == 0
    assert main(["--from", str(source), "--readme", str(readme), "--check"]) == 0
    assert main(["--from", str(tmp_path / "missing.json"), "--readme", str(readme)]) == 2
