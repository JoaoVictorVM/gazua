"""Run records, verdicts, agent mode, reports, baseline and verify over an HTTP target."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
from http_support import (
    LEGIT_REQUEST,
    READ_TOOL,
    AgentServer,
    HttpProject,
    SpanSpec,
)
from tools_factory import CANARY
from verify_support import accepted, baseline_document, gazua, latest_run

from gazua.reports.models import build_run_json_schema
from gazua.reports.rendering import render_report
from gazua.reports.storage import parse_run_document
from gazua.runtime.run_models import EXECUTION_STATUSES


def test_run_records_verdicts_and_agent_states_are_unchanged_over_http(tmp_path: Path) -> None:
    with AgentServer("vulnerable") as target:
        project = HttpProject(tmp_path, target.url())

        result = project.run_agent(repetitions=3)

        engine = result.engine
        keys = {record.request_key for record in engine.records}
        planned = {slot.request_key for context in result.contexts for slot in context.requests}
        assert planned <= keys
        assert all(record.status in EXECUTION_STATUSES for record in engine.records)
        assert all(record.status == "completed" for record in engine.records)
        assert engine.cleanup == "absent"
        for item in result.verdicts.results:
            assert item.planned == 3
            assert item.evaluated + item.unknown + item.not_applicable_count == item.planned
            assert item.state == "finding"
            assert item.rate == 1.0
            assert item.upper_bound is not None
        assert result.legitimate_use.succeeded == 1
        assert result.selection.repetitions == 3
        assert result.exit_code == 1
        # Indirect entries need a local Python tool, so they are reported, not dropped.
        assert all(context.mold.entry == "user_message" for context in result.contexts)


def test_indirect_and_argument_signals_are_not_tested_over_http(tmp_path: Path) -> None:
    with AgentServer("vulnerable") as target:
        project = HttpProject(tmp_path, target.url())
        tools = dict(project.config["tools"])
        tools[READ_TOOL] = {"sensitive": False, "owner_arg": "user_id", "actor_arg": "actor"}
        project.update(
            tools=tools,
            fixtures={
                "attacker": {"id": "attacker-1"},
                "victim": {
                    "id": "victim-1",
                    "records": [{"tool": READ_TOOL, "id_arg": "order_id", "id": "order-1"}],
                },
            },
            agent_entries={"tool_result": {"tool": READ_TOOL, "request": "Search my order."}},
        )
        project.authorize()

        result = project.run_agent(["idor-05", "secret-05", "permission-06"])

        assert {item.mold_id for item in result.verdicts.results} == {
            "idor-05",
            "secret-05",
            "permission-06",
        }
        for item in result.verdicts.results:
            assert item.state == "not_tested", item.mold_id
            assert item.state_counts.resisted == 0
        codes = {
            item.mold_id: [reason.code for reason in item.reasons]
            for item in result.verdicts.results
        }
        assert codes["idor-05"] == ["tool_returns_unobservable"]
        assert codes["secret-05"] == ["entry_unavailable"]
        assert codes["permission-06"] == ["entry_unavailable"]


def test_expected_tool_uses_trace_not_response_text(tmp_path: Path) -> None:
    with AgentServer("vulnerable") as target:
        project = HttpProject(tmp_path, target.url())
        target.spans = lambda message: [SpanSpec(READ_TOOL)] if message == LEGIT_REQUEST else []

        traced = project.run_agent(["secret-04"]).legitimate_use

        target.spans = lambda message: [SpanSpec("search_docs")]
        wrong = project.run_agent(["secret-04"]).legitimate_use

        target.spans = lambda message: []
        silent = project.run_agent(["secret-04"]).legitimate_use

        project.config.pop("traces")
        project.write()
        untraced = project.run_agent(["secret-04"]).legitimate_use

    assert traced.tasks[0].state == "succeeded"
    assert traced.tasks[0].dry_run is False
    assert wrong.tasks[0].state == "failed"
    assert wrong.tasks[0].reason == "expected_tool_not_called"
    assert silent.tasks[0].state == "not_tested"
    assert silent.tasks[0].reason == "otel_tool_contract_missing"
    assert untraced.tasks[0].state == "not_tested"
    assert untraced.tasks[0].reason == "tool_calls_unobservable"


def test_report_regenerates_without_raw_spans_or_tokens(tmp_path: Path) -> None:
    with AgentServer("vulnerable") as target:
        project = HttpProject(tmp_path, target.url("/api/private-path?tenant=secret-q"))

        result = project.cli("run", "--agent", "--mold", "permission-05")

        tokens = {item.headers["X-Gazua-Trace-Token"] for item in target.requests}
    assert result.returncode == 1, result.stdout + result.stderr
    assert "Target: POST to http://127.0.0.1:" in result.stdout
    assert "HTTP has no dry-run" in result.stdout
    content = (tmp_path / ".gazua" / "run.json").read_bytes()
    data = json.loads(content)
    jsonschema.validate(data, build_run_json_schema())
    assert data["schema_version"] == 6
    assert data["target_adapter"] == "http"
    assert data["mcp"] is None
    assert data["metadata"]["target_ref"] == f"http:http://127.0.0.1:{target.port}"
    assert data["http"] == {
        "origin": f"http://127.0.0.1:{target.port}",
        "traces": {
            "enabled": True,
            "coverage": "complete",
            "accepted_tool_spans": data["http"]["traces"]["accepted_tool_spans"],
            "reason": None,
        },
    }
    assert data["http"]["traces"]["accepted_tool_spans"] >= 2
    loaded = parse_run_document(content)
    html, markdown = render_report(loaded)
    assert "HTTP target" in markdown
    assert "with no dry" in markdown
    assert "HTTP target: POST to" in html
    assert "coverage complete" in html
    published = "\n".join(
        [
            content.decode("utf-8"),
            html,
            markdown,
            result.stdout,
            result.stderr,
            *(
                path.read_text(encoding="utf-8", errors="replace")
                for path in (tmp_path / ".gazua").rglob("*")
                if path.is_file() and path.name != "authorization-v1.json"
            ),
        ]
    )
    for private in (
        "private-path",
        "secret-q",
        "gazua-fixture",
        "private prompt that must never persist",
        "private-service-name",
        "X-Gazua-Trace-Token",
        *tokens,
    ):
        assert private not in published, private


def test_remote_payload_headers_and_spans_do_not_reach_outputs(tmp_path: Path) -> None:
    with AgentServer("server_error") as target:
        project = HttpProject(tmp_path, target.url())

        failed = project.cli("run", "--agent", "--mold", "secret-04")

        target.behavior = "vulnerable"
        leaked = project.cli("run", "--agent", "--mold", "secret-04")

    assert failed.returncode == 2
    assert "private stack trace" not in failed.stdout + failed.stderr
    assert leaked.returncode == 1
    outputs = [leaked.stdout, leaked.stderr]
    outputs.extend(
        path.read_text(encoding="utf-8", errors="replace")
        for path in (tmp_path / ".gazua").rglob("*")
        if path.is_file() and path.suffix in (".json", ".md", ".html", ".jsonl")
    )
    joined = "\n".join(outputs)
    assert "private stack trace" not in joined
    assert "extra field" not in joined
    assert "gazua-fixture" not in joined
    # The declared canary is synthetic data the report shows on purpose; the proof is there.
    assert CANARY in joined


def test_verify_requires_same_authorized_adapter_and_origin(tmp_path: Path) -> None:
    with AgentServer("vulnerable") as target:
        project = HttpProject(tmp_path, target.url(), traces=False)
        project.update(legit_tasks=[])
        project.authorize()
        entry = accepted(project.root, "--agent", "--mold", "secret-04")
        assert entry["mode"] == "agent"

        (tmp_path / ".gazua" / "authorization-v1.json").unlink()
        before = target.count
        refused = gazua(project.root, "verify", "secret-04")
        assert refused.returncode == 2
        assert "authorization" in refused.stderr
        assert target.count == before

        project.authorize()
        target.behavior = "hardened"
        verified = gazua(project.root, "verify", "secret-04")

        assert verified.returncode == 0, verified.stdout + verified.stderr
        assert target.count - before == 20
    run = latest_run(project.root)
    assert run["target_adapter"] == "http"
    [closed] = baseline_document(project.root)["entries"]
    assert closed["status"] == "closed"


def test_verify_cannot_close_a_finding_without_its_http_run(tmp_path: Path) -> None:
    with AgentServer("vulnerable") as target:
        project = HttpProject(tmp_path, target.url(), traces=False)
        project.update(legit_tasks=[])
        project.authorize()
        accepted(project.root, "--agent", "--mold", "secret-04")
        cleaned = gazua(project.root, "clean")
        assert cleaned.returncode == 0
        target.behavior = "hardened"

        verified = gazua(project.root, "verify", "secret-04")

    assert verified.returncode == 2, verified.stdout + verified.stderr
    assert "cannot close" in verified.stderr
    [entry] = baseline_document(project.root)["entries"]
    assert entry["status"] == "open"
