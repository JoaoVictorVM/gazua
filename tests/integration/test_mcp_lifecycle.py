import os
import subprocess
from pathlib import Path

from mcp_support import McpProject


def alive(pid: int) -> bool:
    if os.name == "nt":
        listed = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
            capture_output=True,
            text=True,
            check=False,
        )
        return str(pid) in listed.stdout
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def pids(project: McpProject) -> list[int]:
    path = project.state / "pids.txt"
    return [int(line) for line in path.read_text(encoding="utf-8").split()]


def test_lost_response_does_not_retry_tool_call(tmp_path: Path) -> None:
    project = McpProject(tmp_path / "project")
    project.scenario["hang_on_call"] = True
    project.scenario["pid_file"] = str(project.state / "pids.txt")
    project.save_scenario()

    result = project.run_tools("idor-01", overrides={"timeout": 8})

    assert result.exit_code == 2
    [item] = result.verdicts.results
    assert item.state == "not_tested"
    # The call reached the server once; its answer was lost and it was never sent again.
    assert len(project.calls()) == 1
    [record] = result.engine.records
    assert record.status == "timed_out"


def test_timeout_and_end_of_attempt_kill_process_tree(tmp_path: Path) -> None:
    project = McpProject(tmp_path / "project")
    project.scenario["pid_file"] = str(project.state / "pids.txt")
    project.save_scenario()

    project.run_tools("idor-01")
    project.scenario["hang_on_call"] = True
    project.save_scenario()
    project.run_tools("idor-01", overrides={"timeout": 8})

    started = pids(project)
    # Discovery, then one attempt per run: every server they started is gone.
    assert len(started) >= 4
    assert not [pid for pid in started if alive(pid)]
