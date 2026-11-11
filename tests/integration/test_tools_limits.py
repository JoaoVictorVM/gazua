import threading
from typing import Any

from gazua.runtime.observations import RETURNS_FILE
from gazua.runtime.run_models import ExecutionStarted


def test_records_and_verdicts_drive_output_and_exit(tools_project: Any) -> None:
    result = tools_project.run()

    assert result.run_id == result.engine.run_id == result.verdicts.run_id
    assert [item.attack_key for item in result.verdicts.results] == result.result_order
    executed = {slot.request_key for context in result.contexts for slot in context.requests}
    recorded = {record.request_key for record in result.engine.records}
    assert recorded <= executed
    assert result.engine.planned == len(recorded)
    engine = tools_project.root / ".gazua" / "runs" / result.run_id / "engine"
    for item in result.verdicts.results:
        for proof in item.proof:
            if proof.reference is not None:
                assert (engine / proof.reference).is_file()
    assert list(tools_project.root.rglob(RETURNS_FILE)) == []
    assert not (engine / "private").exists() or not any((engine / "private").iterdir())
    public = "".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in engine.rglob("*")
        if path.is_file()
    )
    assert "GAZUA-CANARY-7f3a9c" not in public
    assert '"note"' not in public
    assert result.has_gated_findings
    assert result.exit_code == 1
    ceiling = [item for item in result.verdicts.results if item.mold_id == "spending-02"]
    assert {item.state for item in ceiling} >= {"finding"}


def test_partial_runs_reset_timeout_and_cleanup(tools_project: Any) -> None:
    limited = tools_project.run(overrides={"max_runs": 2, "concurrency": 1})
    statuses = [record.status for record in limited.engine.records]
    assert statuses.count("skipped_by_limit") == len(statuses) - 2
    skipped = [
        item
        for item in limited.verdicts.results
        if any(reason.code == "max_runs" for reason in item.reasons)
    ]
    assert skipped
    assert {item.state for item in skipped} == {"not_tested"}
    assert limited.exit_code in (0, 1)

    tools_project.write(target={"reset": "tools_target:reset"})
    (tools_project.root / "reset_fail").write_text("x", encoding="utf-8")
    reset = tools_project.run("idor-01")
    assert reset.engine.effective_concurrency == 1
    assert "reset_failed" in reset.engine.operational_errors
    assert {item.state for item in reset.verdicts.results} == {"not_tested"}
    assert reset.exit_code == 2
    (tools_project.root / "reset_fail").unlink()

    tools_project.write()
    (tools_project.root / "slow").write_text("x", encoding="utf-8")
    slow = tools_project.run("secret-01", overrides={"timeout": 3})
    assert {record.status for record in slow.engine.records} == {"timed_out"}
    assert slow.exit_code == 2
    (tools_project.root / "slow").unlink()

    cancel = threading.Event()

    def interrupt(event: Any) -> None:
        if isinstance(event, ExecutionStarted):
            cancel.set()

    stopped = tools_project.run(overrides={"concurrency": 1}, on_event=interrupt, cancel=cancel)
    assert stopped.engine.interrupted
    assert "interrupted" in [item.code for item in stopped.diagnostics]
    assert len(stopped.verdicts.results) == len(stopped.contexts)
    assert stopped.exit_code == 2
