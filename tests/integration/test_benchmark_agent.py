import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest
from benchmarks.selftest.oracle import normalized_scenarios
from benchmarks.selftest.runner import BenchmarkOptions, run_benchmark
from benchmarks.selftest.storage import contained
from benchmarks.selftest.targets.spy import read_effects

from gazua.reports.storage import load_run_document

AGENT_SELECTION = ["idor-06", "idor-09", "permission-10", "secret-05", "spending-04", "output-03"]


def run(root: Path) -> Any:
    return run_benchmark(
        BenchmarkOptions(release="v0.4", molds=AGENT_SELECTION, output=str(root / "out")),
        root=root,
        say=lambda _line: None,
    )


@pytest.fixture(scope="module")
def agent_run(tmp_path_factory: pytest.TempPathFactory) -> Any:
    return run(tmp_path_factory.mktemp("agent"))


def workspace(outcome: Any, variant: str, language: str = "en") -> Path:
    return outcome.folder / "runs" / f"agent-python-{variant}-{language}"


def test_agent_cells_fire_on_vulnerable_and_resist_on_hardened(agent_run: Any) -> None:
    summary = agent_run.summary
    assert agent_run.exit_code == 0, [
        (cell.case_id, cell.language, cell.diagnostics)
        for cell in summary.cells
        if cell.outcome != "passed"
    ]
    for cell in summary.cells:
        assert cell.mode == "agent"
        if cell.variant == "vulnerable":
            assert cell.positive
            assert cell.observed_findings
        else:
            assert cell.observed_findings == []
    # Tools-mode controls and checks are not part of an agent-only selection.
    assert not [cell for cell in summary.cells if cell.kind != "target"]


def test_simulated_model_has_no_oracle_access(agent_run: Any) -> None:
    root = workspace(agent_run, "vulnerable")
    copied = {path.name for path in (root / "selftest_target").glob("*.*")}
    assert copied == {
        "__init__.py",
        "domain.json",
        "domain.py",
        "python_target.py",
        "scripted.py",
        "spy.py",
    }
    # What the target can read: its package and the workspace files Gazua does not own.
    visible = [*(root / "selftest_target").rglob("*.json"), *root.glob("*.json")]
    assert sorted(path.name for path in visible) == ["domain.json", "profile.json"]


def test_indirect_payload_is_delivered_before_effect(agent_run: Any) -> None:
    by_process: dict[str, list[str]] = defaultdict(list)
    folder = workspace(agent_run, "vulnerable") / "effects"
    for path in sorted(folder.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            by_process[path.stem].append(json.loads(line)["kind"])
    # In some attempt the docs tool returned the payload before the record was read.
    assert any(
        "search_docs" in kinds
        and "get_order" in kinds
        and kinds.index("search_docs") < kinds.index("get_order")
        for kinds in by_process.values()
    )
    cell = next(
        item
        for item in agent_run.summary.cells
        if item.mold_id == "idor-06" and item.variant == "vulnerable" and item.language == "en"
    )
    document = load_run_document(contained(agent_run.folder, cell.run_document))
    results = {
        item.attack_key: item for item in document.verdicts.results if item.mold_id == "idor-06"
    }
    [result] = results.values()
    assert result.state == "finding"
    assert not [reason for reason in result.reasons if reason.code == "payload_not_delivered"]


def test_reset_between_cases_not_turns(agent_run: Any) -> None:
    # Each attempt runs in its own worker; both turns of a two-turn attack share it.
    folder = workspace(agent_run, "vulnerable") / "effects"
    turns = []
    for path in folder.glob("*.jsonl"):
        lines = path.read_text(encoding="utf-8").splitlines()
        turns.append(sum('"entrypoint_called"' in line for line in lines))
    assert max(turns) >= 2
    hardened = read_effects(workspace(agent_run, "hardened"))
    assert "delete_account" not in {item["kind"] for item in hardened}
    assert {item["tool"] for item in hardened if item["kind"] == "dispatch_refused"} >= {
        "delete_account",
        "refund",
    }


def test_same_seed_has_same_semantics(agent_run: Any, tmp_path: Path) -> None:
    again = run(tmp_path)

    def semantics(outcome: Any) -> dict[str, Any]:
        found: dict[str, Any] = {}
        for cell in outcome.summary.cells:
            document = load_run_document(contained(outcome.folder, cell.run_document))
            found[f"{cell.case_id}/{cell.language}"] = normalized_scenarios(document, cell.mold_id)
        return found

    assert semantics(again) == semantics(agent_run)
