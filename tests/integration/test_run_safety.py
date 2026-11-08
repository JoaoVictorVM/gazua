import json
import sys
from pathlib import Path
from typing import Any

from gazua.runtime.evidence import PrivateEvidence
from gazua.runtime.run_models import (
    COST_WARNING,
    BudgetWarning,
    ExecutionRecord,
    ExecutionStarted,
    RunPrepared,
)

CANARY = "GAZUA-CANARY-01"
KEY = "sk-" + "Z" * 32

SPY_DRIVER = r"""
import json, os, sys
from pathlib import Path
report = {"credential_reads": [], "environment_listed": False}

def is_credential(name):
    upper = name.upper() if isinstance(name, str) else ""
    suffixes = ("_API_KEY", "_TOKEN", "_SECRET", "_PASSWORD")
    return upper.endswith(suffixes) or upper.startswith("AWS_")

class SpyEnviron(type(os.environ)):
    def __getitem__(self, key):
        if is_credential(key):
            report["credential_reads"].append(key)
        return super().__getitem__(key)
    def __iter__(self):
        report["environment_listed"] = True
        return super().__iter__()

os.environ.__class__ = SpyEnviron
root = Path(sys.argv[1])
sys.path.insert(0, str(root))
from gazua.config.models import GazuaConfig
from gazua.runtime.engine import execute_plan, prepare_run
from gazua.runtime.run_models import ExecutionRequest

config = GazuaConfig.model_validate({
    "schema_version": 1, "entrypoint": "agent_target:entrypoint", "canaries": [sys.argv[2]],
})
request = ExecutionRequest.model_validate({
    "key": "leak-1", "mold_id": "leak", "repetition": 1, "mode": "agent",
    "executor": "consumer:execute", "payload": {"message": "leak " + sys.argv[3]},
    "requires_receiver": False, "receiver_transport": False, "usage_reporting": False,
})
summary = execute_plan(prepare_run(config, [request], project_root=root))
report["status"] = summary.records[0].status
report["reason"] = summary.records[0].reason
Path(sys.argv[4]).write_text(json.dumps(report))
"""


def public_text(root: Path) -> str:
    return "".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in (root / ".gazua").rglob("*")
        if path.is_file()
    )


def test_cost_without_usage_or_estimate_warns_before_attack(engine_project: Any) -> None:
    requests = [engine_project.request(f"m{index}-1", "echo x") for index in range(3)]

    summary, events = engine_project.run(requests, {"max_cost": 1, "max_runs": 2})

    prepared = events[0]
    assert isinstance(prepared, RunPrepared)
    assert COST_WARNING == (
        "Warning: max_cost does not apply without reported usage or cost_per_run."
    )
    assert COST_WARNING in prepared.lines()
    first_start = next(i for i, event in enumerate(events) if isinstance(event, ExecutionStarted))
    assert first_start > 0
    assert summary.cost_source == "unavailable"
    assert summary.cost_coverage == "incomplete"
    assert not summary.budget_guaranteed
    assert summary.started == 2
    # Skipped entries are recorded when admission closes, possibly before active ones finish.
    skipped = [record for record in summary.records if record.status == "skipped_by_limit"]
    assert [record.reason for record in skipped] == ["max_runs"]

    estimated, estimated_events = engine_project.run(
        requests, {"max_cost": 0.25, "cost_per_run": 0.1}
    )
    assert COST_WARNING not in estimated_events[0].lines()
    assert estimated.started == 2
    assert estimated.reserved_estimate_usd == "0.2"
    assert estimated.budget_guaranteed
    skipped = [record for record in estimated.records if record.status == "skipped_by_limit"]
    assert [record.reason for record in skipped] == ["max_cost"]


def test_partial_usage_and_inflight_cost_are_not_claimed_as_hard_budget(
    engine_project: Any,
) -> None:
    requests = [
        engine_project.request(
            "a-1", "usage 0.6", usage_reporting=True, payload={"usage_complete": True}
        ),
        engine_project.request("b-1", "echo none", usage_reporting=True),
        engine_project.request(
            "c-1", "usage 0.6", usage_reporting=True, payload={"usage_complete": True}
        ),
        engine_project.request("d-1", "echo never", usage_reporting=True),
    ]

    summary, events = engine_project.run(requests, {"max_cost": 1, "concurrency": 1})

    records = {record.request_key: record for record in summary.records}
    assert records["a-1"].reported_cost_usd == "0.6"
    assert records["a-1"].usage_complete
    assert records["b-1"].reported_cost_usd is None
    assert not records["b-1"].usage_complete
    assert records["c-1"].reported_cost_usd == "0.6"
    assert (records["d-1"].status, records["d-1"].reason) == ("skipped_by_limit", "max_cost")
    assert summary.cost_source == "reported"
    assert summary.cost_coverage == "incomplete"
    assert not summary.budget_guaranteed
    assert summary.reported_cost_usd == "1.2"
    warnings = [event for event in events if isinstance(event, BudgetWarning)]
    assert [warning.reason for warning in warnings] == ["cost_unavailable", "max_cost"]
    assert warnings[0].message == COST_WARNING
    assert "may exceed" in warnings[1].message


def test_no_provider_key_read_and_no_raw_secret_in_public_output(
    engine_project: Any, run_isolated: Any, clean_environment: Any, tmp_path: Path
) -> None:
    driver = engine_project.root / "spy_driver.py"
    driver.write_text(SPY_DRIVER, encoding="utf-8")
    report_path = tmp_path / "report.json"
    environment = {
        **clean_environment(),
        "OPENAI_API_KEY": "sentinel-not-a-real-key",
        "ANTHROPIC_API_KEY": "sentinel-not-a-real-key",
    }

    result = run_isolated(
        [sys.executable, driver, engine_project.root, CANARY, f"{CANARY} {KEY}", report_path],
        cwd=engine_project.root,
        env=environment,
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["credential_reads"] == []
    assert report["environment_listed"] is False
    assert (report["status"], report["reason"]) == ("crashed", "agent_crashed")
    for text in (result.stdout, result.stderr, public_text(engine_project.root)):
        assert CANARY not in text
        assert KEY not in text
        assert "Traceback" not in text
    stderr_files = list((engine_project.root / ".gazua").rglob("stderr.redacted.txt"))
    assert stderr_files
    assert "[redacted-canary]" in stderr_files[0].read_text(encoding="utf-8")


def test_private_evidence_is_consumed_and_removed_without_losing_canary_signal(
    engine_project: Any,
) -> None:
    seen: list[tuple[ExecutionRecord, PrivateEvidence, bool]] = []
    config = engine_project.config(canaries=[CANARY])

    def on_evidence(record: ExecutionRecord, evidence: PrivateEvidence) -> None:
        private = engine_project.root / ".gazua" / "runs" / record.run_id / "engine" / "private"
        seen.append((record, evidence, (private / record.execution_id).is_dir()))

    requests = [
        engine_project.request(
            "exfil-1",
            f"exfil secret {CANARY}",
            requires_receiver=True,
            receiver_transport=True,
        )
    ]
    summary, _ = engine_project.run(requests, config=config, on_evidence=on_evidence)

    ((record, evidence, private_existed),) = seen
    assert private_existed
    assert record.status == "completed"
    assert record.evidence_complete
    (hit,) = evidence.receiver_hits
    assert CANARY.encode() in hit.body
    assert hit.record.logical_url == "https://receiver.gazua.test/collect"
    assert evidence.complete
    engine = engine_project.root / ".gazua" / "runs" / summary.run_id / "engine"
    assert not (engine / "private").exists()
    assert record.receiver_hits is not None
    assert (engine / record.receiver_hits).is_file()
    bodies = (engine / "executions" / record.execution_id / "hit-bodies.redacted.jsonl").read_text(
        encoding="utf-8"
    )
    assert "[redacted-canary]" in bodies
    assert CANARY not in public_text(engine_project.root)
