import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from gazua.typescript import process as runner_process
from gazua.typescript.models import RunnerOpen, RunnerReady
from gazua.typescript.process import LAUNCHER, RunnerFailed, RunnerProcess, runner_command

SECRET = "GAZUA-CANARY-7f3a9c"  # noqa: S105


def open_message() -> RunnerOpen:
    return RunnerOpen.model_validate(
        {
            "protocol_version": 1,
            "type": "open",
            "request_id": "1",
            "operation": "describe",
            "module": "agent.js",
            "exports": {
                "entrypoint": "respond",
                "reset": None,
                "as_user": None,
                "output_sink": None,
            },
        }
    )


def fake_package(root: Path, runner: str) -> None:
    folder = root / "node_modules" / "gazua"
    folder.mkdir(parents=True)
    (folder / "package.json").write_text(
        json.dumps(
            {
                "name": "gazua",
                "version": "0.1.0",
                "type": "module",
                "exports": {"./runner": "./runner.js"},
            }
        ),
        encoding="utf-8",
    )
    (folder / "runner.js").write_text(runner, encoding="utf-8")


def failure(root: Path, node: str) -> RunnerFailed:
    process = RunnerProcess(node, root, root / "session.json")
    process.start()
    try:
        with pytest.raises(RunnerFailed) as caught:
            process.request(open_message(), RunnerReady, deadline=time.monotonic() + 30)
    finally:
        process.close()
    return caught.value


def test_runner_uses_argv_without_shell_and_sanitizes_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert LAUNCHER.is_file()
    assert runner_command("node", tmp_path) == ["node", str(LAUNCHER), str(tmp_path)]

    seen: dict[str, Any] = {}

    class Recorder:
        def __init__(self, command: list[str], **options: Any) -> None:
            seen.update(options, command=command)
            raise OSError("not started")

    monkeypatch.setattr(runner_process.subprocess, "Popen", Recorder)
    with pytest.raises(RunnerFailed) as refused:
        RunnerProcess("node", tmp_path, tmp_path / "session.json").start()
    assert refused.value.code == "typescript_node_missing"
    assert seen["shell"] is False
    assert seen["command"] == ["node", str(LAUNCHER), str(tmp_path)]
    assert seen["cwd"] == tmp_path
    assert seen["env"]["GAZUA_SESSION"] == str(tmp_path / "session.json")
    assert seen["stdout"] == subprocess.PIPE
    assert seen["stderr"] == subprocess.PIPE
    monkeypatch.undo()

    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is not installed.")
    missing = tmp_path / "missing"
    missing.mkdir()
    assert failure(missing, node).code == "typescript_package_missing"

    noisy = tmp_path / "noisy"
    noisy.mkdir()
    fake_package(
        noisy,
        f"export function main() {{ process.stderr.write('{SECRET} trace'); "
        f"process.stdout.write('{SECRET} is not protocol\\n'); }}\n",
    )
    found = failure(noisy, node)
    assert found.code == "typescript_protocol_error"
    assert SECRET not in str(found)
    assert SECRET not in repr(found.args)

    crashed = tmp_path / "crashed"
    crashed.mkdir()
    fake_package(crashed, f"export function main() {{ throw new Error('{SECRET}'); }}\n")
    lost = failure(crashed, node)
    assert lost.code == "typescript_runner_exited"
    assert SECRET not in str(lost)
