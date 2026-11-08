import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from gazua.config.models import GazuaConfig
from gazua.diagnostics import ConfigError
from gazua.runtime.engine import prepare_run
from gazua.runtime.run_models import (
    EXECUTION_SCHEMA_FILE,
    RECEIVER_HIT_SCHEMA_FILE,
    ExecutionRecord,
    ExecutionRequest,
    LimitOverrides,
    ReceiverHit,
    RunPrepared,
    render_execution_json_schema,
    render_receiver_hit_json_schema,
)
from gazua.runtime.session_models import packaged_schema
from gazua.runtime.tools import ToolSummary


def config_of(**document: Any) -> GazuaConfig:
    return GazuaConfig.model_validate({"schema_version": 1, **document})


def request(key: str = "GAZUA-secret-07-1", **overrides: Any) -> ExecutionRequest:
    data: dict[str, Any] = {
        "key": key,
        "mold_id": "secret-07",
        "repetition": 1,
        "mode": "agent",
        "executor": "test_consumer:execute",
        "payload": {"message": "GAZUA synthetic attack"},
        "requires_receiver": False,
        "receiver_transport": False,
        "usage_reporting": False,
    }
    data.update(overrides)
    return ExecutionRequest.model_validate(data)


RECORD: dict[str, Any] = {
    "schema_version": 1,
    "run_id": "GAZUA-run-01",
    "execution_id": "GAZUA-exec-0001",
    "request_key": "GAZUA-secret-07-1",
    "mold_id": "secret-07",
    "repetition": 1,
    "attempt": 1,
    "status": "timed_out",
    "reason": "attack_timeout",
    "started_at": "2026-11-07T12:00:00Z",
    "finished_at": "2026-11-07T12:02:00Z",
    "duration_ms": 120000,
    "exit_code": None,
    "admitted_tool_calls": 3,
    "evidence_complete": False,
    "truncated_tail": True,
    "reported_cost_usd": None,
    "estimated_cost_usd": "0.01",
    "usage_complete": False,
    "call_log": "executions/GAZUA-exec-0001/calls.redacted.jsonl",
    "receiver_hits": None,
    "output": None,
    "reset_before": "succeeded",
}
HIT: dict[str, Any] = {
    "schema_version": 1,
    "hit_id": "GAZUA-hit-1",
    "run_id": "GAZUA-run-01",
    "execution_id": "GAZUA-exec-0001",
    "received_at": "2026-11-07T12:00:01Z",
    "method": "POST",
    "logical_url": "https://receiver.gazua.test/collect",
    "body_size": 15,
    "truncated": False,
    "evidence": None,
}


def test_plan_rejects_duplicate_keys_invalid_limits_and_multiple_targets(
    tmp_path: Path,
) -> None:
    config = config_of(entrypoint="agent_module:run", target={"reset": "agent_module:reset"})

    with pytest.raises(ConfigError) as duplicate:
        prepare_run(config, [request(), request()], project_root=tmp_path)
    assert duplicate.value.diagnostics[0].code == "duplicate_request"

    with pytest.raises(ConfigError) as many:
        prepare_run([config, config], [request()], project_root=tmp_path)  # type: ignore[arg-type]
    assert many.value.diagnostics[0].code == "multiple_targets"

    with pytest.raises(ConfigError) as empty:
        prepare_run(config, [], project_root=tmp_path)
    assert empty.value.diagnostics[0].code == "empty_plan"

    for invalid in ({"max_runs": 0}, {"timeout": -1}, {"concurrency": 0}, {"max_cost": 0}):
        with pytest.raises(ValidationError):
            LimitOverrides.model_validate(invalid)
    with pytest.raises(ValidationError):
        request(executor="not a reference")
    with pytest.raises(ValidationError):
        request(repetition=0)

    plan = prepare_run(
        config,
        [request(), request("GAZUA-secret-07-2", repetition=2)],
        LimitOverrides(max_runs=1, timeout=5),
        project_root=tmp_path,
    )

    assert plan.limits.max_runs == 1
    assert plan.limits.timeout == 5
    assert plan.limits.max_tool_calls == 50
    assert plan.requested_concurrency == 2
    assert plan.effective_concurrency == 1
    assert plan.cost_source == "unavailable"
    assert plan.engine_root == tmp_path.resolve() / ".gazua" / "runs" / plan.run_id / "engine"
    assert plan.run_id.startswith("GAZUA-run-")
    # Preparing never imports the target.
    assert not (tmp_path / ".gazua").exists()


def test_cost_source_prefers_the_estimate_over_reported_usage(tmp_path: Path) -> None:
    config = config_of(entrypoint="agent_module:run")
    reported = prepare_run(config, [request(usage_reporting=True)], project_root=tmp_path)
    estimated = prepare_run(
        config,
        [request(usage_reporting=True)],
        LimitOverrides(cost_per_run=0.01),
        project_root=tmp_path,
    )

    assert reported.cost_source == "reported"
    assert reported.effective_concurrency == 2
    assert estimated.cost_source == "estimated"


def test_execution_and_receiver_records_match_packaged_schemas() -> None:
    assert packaged_schema(EXECUTION_SCHEMA_FILE) == render_execution_json_schema()
    assert packaged_schema(RECEIVER_HIT_SCHEMA_FILE) == render_receiver_hit_json_schema()
    execution = Draft202012Validator(json.loads(packaged_schema(EXECUTION_SCHEMA_FILE)))
    hit = Draft202012Validator(json.loads(packaged_schema(RECEIVER_HIT_SCHEMA_FILE)))

    record = ExecutionRecord.model_validate(RECORD)
    execution.validate(record.model_dump(mode="json"))
    hit.validate(ReceiverHit.model_validate(HIT).model_dump(mode="json"))

    # Absences are explicit fields, never a missing key that a reader could take as success.
    for name in ("reported_cost_usd", "receiver_hits", "evidence_complete"):
        incomplete = {key: value for key, value in RECORD.items() if key != name}
        assert not execution.is_valid(incomplete)
        with pytest.raises(ValidationError):
            ExecutionRecord.model_validate(incomplete)
    for status in ("resisted", "passed", "vulnerable"):
        assert not execution.is_valid({**RECORD, "status": status})
    assert not execution.is_valid({**RECORD, "reported_cost_usd": 0.5})
    assert not execution.is_valid({**RECORD, "execution_id": "../../escape"})
    assert not execution.is_valid({**RECORD, "call_log": "/etc/passwd"})
    assert not hit.is_valid({**HIT, "method": "CONNECT"})


def test_prepared_summary_text_shows_total_shape_limit_and_tools() -> None:
    tools = ToolSummary(
        real=("a", "b", "c"),
        dry_run=tuple(f"d{index}" for index in range(9)),
        low_fidelity=(),
        warnings=(),
    )
    event = RunPrepared(
        seq=1,
        planned=225,
        molds=45,
        repetitions=5,
        max_runs=300,
        max_retries=2,
        requested_concurrency=2,
        effective_concurrency=2,
        tools=tools,
        cost_source="unavailable",
    )

    assert event.lines()[0] == (
        "Running 225 executions: 45 molds x 5 repetitions. Limit 300. 3 real tools, 9 in dry-run."
    )
