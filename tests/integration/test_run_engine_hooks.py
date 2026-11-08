import json
import os
import signal
import subprocess
import sys
import time
from typing import Any

from gazua.runtime.run_models import ExecutionFinished, RunEvent, RunSummary

DRIVER = r"""
import json, signal, sys
from pathlib import Path
if sys.platform == "win32":
    # A console break reaches this process group only; it stands in for Ctrl+C.
    signal.signal(signal.SIGBREAK, signal.default_int_handler)
root = Path(sys.argv[1])
sys.path.insert(0, str(root))
from gazua.config.models import GazuaConfig
from gazua.runtime.engine import execute_plan, prepare_run
from gazua.runtime.run_models import ExecutionRequest, ExecutionStarted

config = GazuaConfig.model_validate({
    "schema_version": 1,
    "entrypoint": "agent_target:entrypoint",
    "target": {"reset": "agent_target:reset"},
    "limits": {"timeout": 20},
})
def request(key, message):
    return ExecutionRequest.model_validate({
        "key": key, "mold_id": key, "repetition": 1, "mode": "agent",
        "executor": "consumer:execute", "payload": {"message": message},
        "requires_receiver": False, "receiver_transport": False, "usage_reporting": False,
    })
plan = prepare_run(
    config,
    [request("first", "echo a"), request("held", "hold 60"), request("never", "echo b")],
    project_root=root,
)
def on_event(event):
    if isinstance(event, ExecutionStarted):
        print("started " + event.request_key, flush=True)
summary = execute_plan(plan, on_event)
(root / "summary-out.json").write_text(summary.model_dump_json())
print("done", flush=True)
"""


def resets(marks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [mark for mark in marks if mark["kind"] == "reset"]


def test_engine_invokes_entrypoint_and_reset_per_attack(engine_project: Any) -> None:
    requests = [engine_project.request(f"m{index}-1", f"echo {index}") for index in range(3)]

    summary, _ = engine_project.run(requests, config=engine_project.config(reset=True))

    marks = engine_project.marks()
    starts = [mark for mark in marks if mark["kind"] == "entry_start"]
    assert len(starts) == 3
    for start in starts:
        before = [mark for mark in marks if mark["pid"] == start["pid"]]
        assert [mark["kind"] for mark in before] == ["reset", "entry_start", "entry_end"]
    final = resets(marks)[-1]
    assert final["pid"] not in {start["pid"] for start in starts}
    assert final["t"] > max(mark["t"] for mark in marks if mark["kind"] == "entry_end")
    assert len(resets(marks)) == 4
    assert {record.reset_before for record in summary.records} == {"succeeded"}
    assert summary.cleanup == "succeeded"
    assert [record.output for record in summary.records if record.output]


def test_config_limits_and_reset_are_enforced(engine_project: Any) -> None:
    config = engine_project.config(
        reset=True,
        limits={"timeout": 3, "max_tool_calls": 4, "concurrency": 3, "max_runs": 3},
    )
    requests = [
        engine_project.request("loop-1", "loop"),
        engine_project.request("sleep-1", "sleep"),
        engine_project.request("echo-1", "echo ok"),
        engine_project.request("echo-2", "echo extra"),
    ]

    summary, _ = engine_project.run(requests, config=config)

    records = {record.request_key: record for record in summary.records}
    assert summary.limits.timeout == 3
    assert summary.effective_concurrency == 1
    assert (records["loop-1"].status, records["loop-1"].admitted_tool_calls) == (
        "killed_at_ceiling",
        4,
    )
    effects = [mark for mark in engine_project.marks() if mark["kind"] == "tool_effect"]
    assert len(effects) <= 4
    assert records["sleep-1"].status == "timed_out"
    assert records["echo-1"].status == "completed"
    assert (records["echo-2"].status, records["echo-2"].reason) == ("skipped_by_limit", "max_runs")
    assert len(resets(engine_project.marks())) == 4


def test_reset_failure_blocks_pending_attacks_and_still_attempts_cleanup(
    engine_project: Any,
) -> None:
    (engine_project.root / "reset_fail").write_text("", encoding="utf-8")
    requests = [engine_project.request(f"m{index}-1", "echo x") for index in range(3)]

    summary, _ = engine_project.run(requests, config=engine_project.config(reset=True))

    statuses = [(record.status, record.reason, record.reset_before) for record in summary.records]
    assert statuses == [
        ("reset_failed", "reset_failed", "failed"),
        ("reset_failed", "reset_failed", "not_started"),
        ("reset_failed", "reset_failed", "not_started"),
    ]
    marks = engine_project.marks()
    assert not [mark for mark in marks if mark["kind"] == "entry_start"]
    assert len(resets(marks)) == 2
    assert summary.cleanup == "failed"
    assert "reset_failed" in summary.operational_errors
    assert "cleanup_failed" in summary.operational_errors
    assert summary.started == 1
    public = engine_project.root / ".gazua" / "runs" / summary.run_id / "engine"
    assert "private detail" not in "".join(
        path.read_text(encoding="utf-8") for path in public.rglob("*") if path.is_file()
    )


def test_ctrl_c_writes_partial_summary_and_runs_bounded_final_reset(
    engine_project: Any, clean_environment: Any
) -> None:
    driver = engine_project.root / "driver.py"
    driver.write_text(DRIVER, encoding="utf-8")
    options: dict[str, Any] = {}
    if sys.platform == "win32":
        options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    process = subprocess.Popen(
        [sys.executable, str(driver), str(engine_project.root)],
        cwd=engine_project.root,
        env=clean_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        **options,
    )
    assert process.stdout is not None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        line = process.stdout.readline()
        if line.strip() == "started held":
            break
    while time.monotonic() < deadline and not any(
        mark["kind"] == "entry_start" and mark["command"] == "hold"
        for mark in engine_project.marks()
    ):
        time.sleep(0.05)
    interrupted_at = time.time()
    if sys.platform == "win32":
        os.kill(process.pid, signal.CTRL_BREAK_EVENT)
    else:
        process.send_signal(signal.SIGINT)
    remaining, errors = process.communicate(timeout=60)

    assert process.returncode == 0, errors
    assert "done" in remaining
    summary = RunSummary.model_validate_json(
        (engine_project.root / "summary-out.json").read_text(encoding="utf-8")
    )
    assert summary.interrupted
    statuses = {record.request_key: (record.status, record.reason) for record in summary.records}
    assert statuses == {
        "first": ("completed", None),
        "held": ("cancelled", "interrupted"),
        "never": ("not_tested", "interrupted"),
    }
    assert summary.cleanup == "succeeded"
    final_resets = [mark for mark in resets(engine_project.marks()) if mark["t"] > interrupted_at]
    assert len(final_resets) == 1
    stored = engine_project.root / ".gazua" / "runs" / summary.run_id / "engine" / "summary.json"
    assert json.loads(stored.read_text(encoding="utf-8"))["interrupted"] is True
    assert "Traceback" not in errors


def test_hung_final_reset_is_killed_and_recorded(engine_project: Any) -> None:
    flag = engine_project.root / "reset_hang"

    def on_event(event: RunEvent) -> None:
        if isinstance(event, ExecutionFinished):
            flag.write_text("", encoding="utf-8")

    from gazua.runtime.engine import execute_plan, prepare_run
    from gazua.runtime.run_models import LimitOverrides

    plan = prepare_run(
        engine_project.config(reset=True),
        [engine_project.request("only-1", "echo x")],
        LimitOverrides(timeout=2),
        project_root=engine_project.root,
    )
    started = time.monotonic()
    summary = execute_plan(plan, on_event)

    assert time.monotonic() - started < 30
    assert summary.records[0].status == "completed"
    assert summary.cleanup == "timed_out"
    assert "cleanup_failed" in summary.operational_errors
    assert len(resets(engine_project.marks())) == 2
