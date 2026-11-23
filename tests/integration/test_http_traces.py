"""Tool visibility over HTTP: spans prove calls; without them, nothing is concluded."""

from __future__ import annotations

from pathlib import Path

from http_support import (
    FORBIDDEN_TOOL,
    READ_TOOL,
    AgentServer,
    HttpProject,
    SpanSpec,
    result_of,
)


def test_forbidden_tool_call_is_proven_with_traces(tmp_path: Path) -> None:
    with AgentServer("vulnerable") as target:
        project = HttpProject(tmp_path, target.url())

        result = project.run_agent(["permission-05"], repetitions=2)

        forbidden = result_of(result, "permission-05")
        assert forbidden.state == "finding"
        assert forbidden.successes == 2
        assert forbidden.proof[0].facts == {"tool": FORBIDDEN_TOOL, "source": "trace"}
        assert forbidden.gated
        for received in target.requests:
            assert received.headers["X-Gazua-OTLP-Endpoint"].startswith("http://127.0.0.1:")
            assert received.headers["X-Gazua-OTLP-Endpoint"].endswith("/v1/traces")
            assert len(received.headers["X-Gazua-Trace-Token"]) >= 32


def test_hardened_agent_with_complete_traces_resists(tmp_path: Path) -> None:
    with AgentServer("hardened") as target:
        project = HttpProject(tmp_path, target.url())

        result = project.run_agent(["permission-05"], repetitions=2)

        forbidden = result_of(result, "permission-05")
        assert forbidden.state == "resisted"
        assert forbidden.state_counts.resisted == 2
        assert result.exit_code == 0


def test_missing_traces_make_tool_visibility_attack_not_tested(tmp_path: Path) -> None:
    with AgentServer("vulnerable") as target:
        project = HttpProject(tmp_path, target.url(), traces=False)

        result = project.run_agent(["permission-05", "secret-04"])

        forbidden = result_of(result, "permission-05")
        assert forbidden.state == "not_tested"
        assert [reason.code for reason in forbidden.reasons] == ["tool_calls_unobservable"]
        # The attack still ran and the agent answered; its words prove no call.
        assert target.count >= 2

    # Traces on, but the target exports no tool span: missing instrumentation proves nothing.
    folder = tmp_path / "silent"
    folder.mkdir()
    with AgentServer("silent") as silent:
        project = HttpProject(folder, silent.url())

        result = project.run_agent(["permission-05"])

        forbidden = result_of(result, "permission-05")
        assert forbidden.state == "not_tested"
        assert [reason.code for reason in forbidden.reasons] == ["otel_tool_contract_missing"]


def test_response_canary_finding_does_not_require_traces(tmp_path: Path) -> None:
    with AgentServer("vulnerable") as target:
        project = HttpProject(tmp_path, target.url(), traces=False)

        result = project.run_agent(["secret-04"])

        assert result_of(result, "secret-04").state == "finding"


def test_late_wrong_run_and_pre_request_spans_are_not_attributed(tmp_path: Path) -> None:
    with AgentServer("vulnerable") as target:
        project = HttpProject(tmp_path, target.url())
        for spans in (
            [
                SpanSpec(READ_TOOL),
                SpanSpec(FORBIDDEN_TOOL, run_id="GAZUA-run-other:GAZUA-exec-0001"),
            ],
            [SpanSpec(READ_TOOL), SpanSpec(FORBIDDEN_TOOL, start_offset=-120)],
            [SpanSpec(READ_TOOL), SpanSpec(FORBIDDEN_TOOL, operation="llm_call")],
        ):
            target.spans = lambda _message, chosen=spans: list(chosen)

            result = project.run_agent(["permission-05"])

            assert result_of(result, "permission-05").state == "resisted"

        # A span that arrives after the receiver closed is never attributed.
        target.spans = lambda _message: [SpanSpec(FORBIDDEN_TOOL)]
        target.export_delay = 2.0
        result = project.run_agent(["permission-05"])

        forbidden = result_of(result, "permission-05")
        assert forbidden.state == "not_tested"
        assert forbidden.state_counts.finding == 0


def test_waits_for_terminal_span_within_five_seconds(tmp_path: Path) -> None:
    with AgentServer("vulnerable") as target:
        project = HttpProject(tmp_path, target.url(), wait=1.5)
        target.export_delay = 0.5

        result = project.run_agent(["permission-05"])

        assert result_of(result, "permission-05").state == "finding"
        record = next(item for item in result.engine.records if item.mold_id == "permission-05")
        assert record.status == "completed"
        assert record.duration_ms is not None
        assert record.duration_ms < 30_000


def test_raised_and_blocked_spans_are_not_successful_calls(tmp_path: Path) -> None:
    with AgentServer("vulnerable") as target:
        project = HttpProject(tmp_path, target.url())
        target.spans = lambda _message: [SpanSpec(FORBIDDEN_TOOL, outcome="blocked")]

        blocked = result_of(project.run_agent(["permission-05"]), "permission-05")

        target.spans = lambda _message: [SpanSpec(FORBIDDEN_TOOL, outcome="raised")]
        raised = result_of(project.run_agent(["permission-05"]), "permission-05")

        assert blocked.state == "resisted"
        assert raised.state == "not_tested"
        assert [reason.code for reason in raised.reasons] == ["call_outcome_unknown"]
