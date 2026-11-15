"""The demo's results repeat: same selection, states, findings, proofs, rates and legitimate use."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from demo_support import semantic

from gazua.catalog.loader import load_catalog
from gazua.config.loader import load_config
from gazua.demo.workspace import prepare_workspace
from gazua.modes.tools import run_tools
from gazua.modes.tools_models import ToolsOptions

# One mold per state path of tools mode on the demo store: a finding with a victim record, a
# proven inapplicability, a tool that is not safe: true, a canary, the sink and the ceiling.
# Twenty full catalogs would take minutes; every full demo below runs the whole catalog.
TWENTY_RUN_MOLDS = ("idor-01", "idor-04", "permission-01", "secret-01", "output-01", "spending-02")


def _normalized(result: Any) -> dict[str, Any]:
    def proof(item: Any) -> dict[str, Any]:
        return item.model_dump(exclude={"execution_id", "reference"})

    return {
        "exit": result.exit_code,
        "order": result.result_order,
        "results": [
            {**item.model_dump(exclude={"proof"}), "proof": [proof(entry) for entry in item.proof]}
            for item in result.verdicts.results
        ],
        "counts": result.engine.counts,
        "statuses": sorted(
            (record.request_key, record.status, record.reason, record.attempt)
            for record in result.engine.records
        ),
        "diagnostics": [item.model_dump() for item in result.diagnostics],
    }


def test_twenty_tools_runs_have_identical_results(tmp_path: Path) -> None:
    workspace = prepare_workspace(tmp_path / "gazua-demo")
    config = load_config(workspace.config_path).config
    entries = tuple(
        entry
        for entry in load_catalog(config, config_dir=workspace.root, release="v0.2").entries
        if entry.mold.id in TWENTY_RUN_MOLDS
    )

    first = _normalized(run_tools(config, entries, ToolsOptions(), workspace.root))

    states = sorted({(item["mold_id"], item["state"]) for item in first["results"]})
    assert states == [
        ("idor-01", "finding"),
        ("idor-04", "not_applicable"),
        ("output-01", "finding"),
        ("output-01", "not_tested"),
        ("permission-01", "not_tested"),
        ("secret-01", "finding"),
        ("spending-02", "finding"),
    ]
    for _ in range(19):
        assert _normalized(run_tools(config, entries, ToolsOptions(), workspace.root)) == first


def test_repeated_full_demo_has_identical_semantic_results(
    spied_demo: Any, clean_demo: Any, reused_demo: Any
) -> None:
    runs = [spied_demo, clean_demo, reused_demo["run"]]
    projections = []
    for run in runs:
        assert run.result.returncode == 1, run.result.stderr
        documents = run.documents()
        projections.append({mode: semantic(documents[mode]) for mode in ("tools", "agent")})

    assert projections[0]["tools"]["findings"]
    assert projections[0]["agent"]["legitimate"]["rate"] == 1.0
    assert projections[1] == projections[0]
    assert projections[2] == projections[0]
