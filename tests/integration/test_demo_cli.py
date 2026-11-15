"""gazua demo runs both real modes against the packaged store, with no key or configuration."""

from __future__ import annotations

from typing import Any

from gazua.catalog.loader import load_catalog
from gazua.catalog.selection import select_molds
from gazua.demo import ENTRYPOINT, MODEL_ID, TARGET_VERSION
from gazua.demo.presentation import SIMULATION_NOTICE
from gazua.demo.workspace import packaged_config


def _mold_ids(mode: str) -> set[str]:
    entries = select_molds(load_catalog(release="v0.2").entries, mode)  # type: ignore[arg-type]
    return {entry.mold.id for entry in entries}


def test_demo_without_configuration_or_key(clean_demo: Any) -> None:
    result = clean_demo.result

    assert result.returncode == 1, result.stderr
    assert "Traceback" not in result.stdout + result.stderr
    assert SIMULATION_NOTICE["en"] in result.stdout
    assert (clean_demo.workspace / "index.html").is_file()
    documents = clean_demo.documents()
    assert sorted(documents) == ["agent", "tools"]
    assert documents["tools"]["findings"]
    assert documents["agent"]["findings"]
    assert "Demo exit code: 1." in result.stdout


def test_tools_then_agent_use_native_engines(clean_demo: Any) -> None:
    stdout = clean_demo.result.stdout
    documents = clean_demo.documents()
    tools, agent = documents["tools"], documents["agent"]

    assert stdout.index("part 1 of 2: tools mode") < stdout.index("part 2 of 2: agent mode")
    assert tools["metadata"]["created_at"] < agent["metadata"]["created_at"]
    assert tools["run_id"] != agent["run_id"]
    for document in (tools, agent):
        assert document["metadata"]["target_ref"] == ENTRYPOINT
        assert document["metadata"]["target_version"] == TARGET_VERSION
        assert document["engine"]["records"]
        assert "call" in {proof["source"] for proof in document["proofs"]}
    assert tools["metadata"]["model"] is None
    assert agent["metadata"]["model"] == MODEL_ID
    assert {item["mold_id"] for item in tools["verdicts"]["results"]} == _mold_ids("tools")
    assert {item["mold_id"] for item in agent["verdicts"]["results"]} == _mold_ids("agent")


def test_default_agent_repetitions_are_five(clean_demo: Any) -> None:
    agent = clean_demo.documents()["agent"]

    assert {item["planned"] for item in agent["verdicts"]["results"]} == {5}
    findings = [item for item in agent["verdicts"]["results"] if item["state"] == "finding"]
    assert findings
    assert all(item["evaluated"] == 5 for item in findings)
    legitimate = agent["legitimate_use"]
    assert legitimate["planned"] == 2
    assert legitimate["succeeded"] == 2


def test_demo_ignores_host_project_config(spied_demo: Any) -> None:
    from conftest import HOSTILE_HOST_CONFIG

    result = spied_demo.result

    assert result.returncode == 1, result.stderr
    assert (spied_demo.host / "gazua.yaml").read_text(encoding="utf-8") == HOSTILE_HOST_CONFIG
    assert (spied_demo.workspace / "gazua.yaml").read_bytes() == packaged_config()
    assert "host_project_that_must_not_load" not in result.stdout + result.stderr
    assert sorted(item.name for item in spied_demo.host.iterdir()) == ["gazua-demo", "gazua.yaml"]
