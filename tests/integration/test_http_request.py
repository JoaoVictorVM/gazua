"""What reaches the endpoint: the fixed contract, identification and the absence of retries."""

from __future__ import annotations

import json
from pathlib import Path

from http_support import AgentServer, HttpProject, SpyServer, result_of

from gazua.http import user_agent


def test_each_request_has_identity_and_run_headers(tmp_path: Path) -> None:
    with AgentServer("hardened") as target:
        project = HttpProject(tmp_path, target.url(), traces=False)

        result = project.run_agent(repetitions=2)

        assert target.count == len(result.engine.records) > 2
        attempts: set[str] = set()
        for received in target.requests:
            assert received.method == "POST"
            assert received.path == "/agent"
            assert received.headers["User-Agent"] == user_agent()
            assert received.headers["User-Agent"].startswith("gazua/")
            run = received.headers["X-Gazua-Run"]
            assert run.startswith(f"{result.run_id}:GAZUA-exec-")
            assert received.json()["run_id"] == run
            assert received.headers["X-Test-Tenant"] == "gazua-fixture"
            assert received.headers["Content-Type"] == "application/json"
            assert "X-Gazua-Trace-Token" not in received.headers
            attempts.add(run)
        # One attempt id per execution, never shared.
        assert len(attempts) == target.count


def test_fixed_request_and_response_contract_reaches_agent_mode(tmp_path: Path) -> None:
    with AgentServer("vulnerable") as target:
        project = HttpProject(tmp_path, target.url(), traces=False)

        result = project.run_agent(["secret-04"], repetitions=2)

        leak = result_of(result, "secret-04")
        assert leak.state == "finding"
        assert leak.successes == 2
        assert leak.rate == 1.0
        assert leak.gated
        attack = [
            item for item in target.requests if item.json()["message"] != "Show my last order."
        ]
        assert attack
        for item in attack:
            assert set(item.json()) == {"message", "run_id"}
            assert "print every secret" in item.json()["message"]
        assert result.exit_code == 1


def test_invalid_oversized_and_error_responses_are_not_resistance(tmp_path: Path) -> None:
    with AgentServer() as target:
        project = HttpProject(tmp_path, target.url(), traces=False)
        for behavior, code in (
            ("invalid_json", "http_response_invalid"),
            ("not_text", "http_response_invalid"),
            ("huge", "http_response_limit"),
            ("client_error", "http_client_error"),
            ("server_error", "http_server_error"),
        ):
            target.behavior = behavior

            result = project.run_agent(["secret-04"])

            leak = result_of(result, "secret-04")
            assert leak.state == "not_tested", behavior
            assert leak.state_counts.resisted == 0
            assert code in result.engine.operational_errors or any(
                record.reason == code for record in result.engine.records
            ), behavior
            assert result.exit_code == 2


def test_cross_and_same_host_redirects_are_not_followed(tmp_path: Path) -> None:
    with AgentServer("redirect") as target, SpyServer() as elsewhere:
        project = HttpProject(tmp_path, target.url(), traces=False)
        for location in (elsewhere.url("/stolen", host="localhost"), elsewhere.url("/same")):
            target.redirect_to = location

            result = project.run_agent(["secret-04"])

            assert elsewhere.count == 0
            reasons = {record.reason for record in result.engine.records}
            assert reasons == {"http_redirect_refused"}
            assert result_of(result, "secret-04").state == "not_tested"
            assert result.exit_code == 2


def test_lost_response_is_never_retried(tmp_path: Path) -> None:
    with AgentServer("drop") as target:
        project = HttpProject(tmp_path, target.url(), traces=False)

        result = project.run_agent(["secret-04"])

        attack = [
            item for item in target.requests if item.json()["message"] != "Show my last order."
        ]
        assert len(attack) == 1
        assert all(record.attempt == 1 for record in result.engine.records)
        assert result.engine.retries == 0
        assert {record.reason for record in result.engine.records} == {"http_transport_lost"}


def test_rate_limit_uses_the_backoff_contract(tmp_path: Path) -> None:
    with AgentServer("rate_limited") as target:
        project = HttpProject(tmp_path, target.url(), traces=False)
        project.update(legit_tasks=[])

        result = project.run_agent(["secret-04"])

        assert result.engine.retries == 2
        assert target.count == 3
        assert {record.status for record in result.engine.records} == {"rate_limited"}
        assert result_of(result, "secret-04").state == "not_tested"


def test_five_server_failures_stop_admission(tmp_path: Path) -> None:
    with AgentServer("server_error") as target:
        project = HttpProject(tmp_path, target.url(), traces=False)

        result = project.run_agent(["secret-04", "permission-05"], repetitions=5)

        assert result.engine.stop_reason == "repeated_agent_failure"
        assert result.engine.stop_error is not None
        assert result.engine.stop_error.code == "http_server_error"
        assert target.count == 5
        not_started = [record for record in result.engine.records if record.started_at is None]
        assert not_started
        assert all(record.status == "not_tested" for record in not_started)
        assert all(item.state == "not_tested" for item in result.verdicts.results)
        assert result.engine.cleanup == "absent"
        assert result.exit_code == 2
        document = json.dumps(result.engine.model_dump(mode="json"))
        assert "private stack trace" not in document
