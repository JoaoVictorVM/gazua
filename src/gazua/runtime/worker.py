"""Bootstrap of one supervised process: an attack attempt, a preflight or the final reset.

The engine starts this module with the path of a JSON job. Nothing runs before the release
line arrives on stdin, which the engine sends only once the process tree is supervised. The
session is put in force before the target is imported, and the result goes to a JSON file
written atomically. Messages and tracebacks from the target are never printed or recorded.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

EXIT_OK = 0
EXIT_BAD_JOB = 64
EXIT_INTERNAL = 70


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    """What an executor receives besides its request. It holds no attack verdict."""

    run_id: str
    execution_id: str
    config: Any
    entrypoint: str | None
    directory: Path
    session_path: Path
    call_log: Path


Executor = Callable[[Mapping[str, Any], ExecutionContext], object]


def _write_json(path: Path, document: Mapping[str, Any]) -> None:
    content = json.dumps(document, ensure_ascii=True, allow_nan=False)
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=".result-", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _emit(kind: str, payload: Mapping[str, Any]) -> None:
    from gazua.integration.channel import channel_for
    from gazua.integration.session import Session, session_state

    state = session_state()
    if isinstance(state, Session) and state.execution is not None:
        channel_for(state.execution).emit(kind, payload, sync=True)


def _reset(reference: str | None) -> dict[str, Any]:
    from gazua.runtime.hooks import ResetFailed, call_reset

    if reference is None:
        return {"status": "ok", "reset": "absent"}
    try:
        call_reset(reference)
    except ResetFailed:
        return {"status": "reset_failed"}
    return {"status": "ok", "reset": "succeeded"}


def _executor_result(value: object) -> dict[str, Any]:
    if value is None:
        return {"status": "ok", "output": None, "usage_complete": False}
    if not isinstance(value, Mapping):
        return {"status": "error", "code": "executor_result_invalid"}
    data = cast("Mapping[str, Any]", value)
    if not set(data) <= {"output", "usage_complete"}:
        return {"status": "error", "code": "executor_result_invalid"}
    usage_complete = data.get("usage_complete", False)
    if not isinstance(usage_complete, bool):
        return {"status": "error", "code": "executor_result_invalid"}
    try:
        json.dumps(data.get("output"), allow_nan=False)
    except (TypeError, ValueError):
        return {"status": "error", "code": "executor_result_invalid"}
    return {"status": "ok", "output": data.get("output"), "usage_complete": usage_complete}


def _attack(job: Mapping[str, Any]) -> dict[str, Any]:
    from gazua.config.models import GazuaConfig
    from gazua.config.references import resolve_reference
    from gazua.diagnostics import ConfigError
    from gazua.integration.errors import GazuaBlockedError
    from gazua.integration.telemetry import GazuaRateLimited
    from gazua.runtime.hooks import HookError, RateLimited

    reset = job.get("reset")
    if reset is not None:
        _emit("reset_started", {})
        outcome = _reset(reset)
        _emit("reset_before", {"outcome": "failed" if outcome["status"] != "ok" else "succeeded"})
        if outcome["status"] != "ok":
            return outcome
    try:
        executor = cast("Executor", resolve_reference(job["executor"], "executor"))
    except ConfigError:
        return {"status": "error", "code": "executor_unavailable"}
    context = ExecutionContext(
        run_id=job["run_id"],
        execution_id=job["execution_id"],
        config=GazuaConfig.model_validate(job["config"]),
        entrypoint=job.get("entrypoint"),
        directory=Path(job["directory"]),
        session_path=Path(job["session"]),
        call_log=Path(job["call_log"]),
    )
    try:
        value = executor(dict(job["request"]), context)
    except RateLimited as limited:
        return {"status": "rate_limited", "retry_after": limited.retry_after}
    except GazuaRateLimited as limited:
        return {"status": "rate_limited", "retry_after": limited.retry_after}
    except HookError as failure:
        return {"status": "error", "code": failure.code}
    except GazuaBlockedError as blocked:
        return {"status": "error", "code": "blocked", "reason": blocked.reason}
    # The executor runs the target's code; any failure is recorded by class, never by message.
    except (Exception, SystemExit) as failure:  # noqa: BLE001
        return {"status": "error", "code": "executor_error", "error_type": type(failure).__name__}
    return _executor_result(value)


def _preflight(job: Mapping[str, Any]) -> dict[str, Any]:
    from gazua.config.models import GazuaConfig
    from gazua.config.references import resolve_reference
    from gazua.diagnostics import ConfigError
    from gazua.runtime.tools import ToolInventory

    config = GazuaConfig.model_validate(job["config"])
    entrypoint = job.get("entrypoint")
    if entrypoint is not None:
        try:
            resolve_reference(entrypoint, "entrypoint")
        except ConfigError as failure:
            return {"status": "error", "code": failure.diagnostics[0].code}
    summary = ToolInventory.collect(config).summary()
    return {
        "status": "ok",
        "tools": {
            "real": list(summary.real),
            "dry_run": list(summary.dry_run),
            "low_fidelity": list(summary.low_fidelity),
            "warnings": [
                {"code": item.code, "field": item.field, "message": item.message}
                for item in summary.warnings
            ],
        },
    }


def run_job(job: Mapping[str, Any]) -> dict[str, Any]:
    root = str(job["project_root"])
    os.chdir(root)
    if root not in sys.path:
        sys.path.insert(0, root)
    session = job.get("session")
    if session is not None:
        from gazua.integration.session import SESSION_ENV

        os.environ[SESSION_ENV] = str(session)
    kind = job["kind"]
    if kind == "attack":
        return _attack(job)
    if kind == "preflight":
        return _preflight(job)
    if kind == "reset":
        return _reset(job.get("reset"))
    return {"status": "error", "code": "job_kind"}


def main(arguments: list[str]) -> int:
    if sys.stdin.buffer.readline() != b"go\n":
        return EXIT_BAD_JOB
    try:
        job_path = Path(arguments[0])
        job = json.loads(job_path.read_text(encoding="utf-8"))
        result_path = Path(job["result"])
    except (IndexError, OSError, ValueError, KeyError, TypeError):
        return EXIT_BAD_JOB
    try:
        result = run_job(job)
    # Anything that escapes, from the target or from Gazua, ends the worker without a traceback.
    except BaseException as failure:  # noqa: BLE001
        result = {"status": "error", "code": "worker_error", "error_type": type(failure).__name__}
    try:
        _write_json(result_path, result)
    except (OSError, ValueError):
        return EXIT_INTERNAL
    return EXIT_OK


if __name__ == "__main__":
    try:
        code = main(sys.argv[1:])
    except BaseException:  # noqa: BLE001
        code = EXIT_INTERNAL
    sys.stdout.flush()
    os._exit(code)
