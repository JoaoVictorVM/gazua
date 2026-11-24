"""Agent mode executor for a TypeScript target, run by the engine inside each supervised worker.

One Node runner serves every turn of one attempt, so a two-turn attack keeps the agent's state;
retries, repetitions and legitimate tasks get their own worker and runner. The mold is bound and
checked exactly as for a Python entrypoint; only the delivery changes. The npm package inside
Node writes the call log, events and private returns this worker's session names, so verdicts
read the same evidence for both languages.
"""

from __future__ import annotations

import time
from collections.abc import Generator, Mapping
from contextlib import contextmanager
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Final

from pydantic import JsonValue

from gazua.config.models import GazuaConfig
from gazua.diagnostics import ConfigError
from gazua.integration.errors import GazuaBlockedError
from gazua.runtime.worker import ExecutionContext
from gazua.typescript.models import (
    PROTOCOL_VERSION,
    RunnerError,
    RunnerExports,
    RunnerInvoke,
    RunnerOpen,
    RunnerReady,
    RunnerReset,
    RunnerResetDone,
    RunnerResult,
    RunnerSink,
    RunnerSinkResult,
    TypeScriptProvenance,
)
from gazua.typescript.process import RunnerFailed, RunnerProcess

# The worker must write its result before the supervisor's deadline kills it.
DEADLINE_MARGIN: Final = 0.5
HASH_FIELD: Final = "typescript_module_sha256"


class TypeScriptRunBlocked(GazuaBlockedError):
    """The runner could not serve the attempt. ``reason`` starts with ``typescript_``."""


def failure_code(code: str) -> str:
    return code if code.startswith("typescript_") else f"typescript_{code}"


def _exports(config: GazuaConfig) -> RunnerExports:
    target = config.typescript
    if target is None:
        raise TypeScriptRunBlocked("typescript_target_missing")
    return RunnerExports(
        entrypoint=target.entrypoint_export,
        reset=target.reset_export,
        as_user=target.as_user_export,
        output_sink=target.output_sink_export,
    )


def _deadline(context: ExecutionContext) -> float:
    config: GazuaConfig = context.config
    if context.deadline is not None:
        return context.deadline - DEADLINE_MARGIN
    return time.monotonic() + float(config.limits.timeout) - DEADLINE_MARGIN


def base_version(text: str) -> tuple[int, ...]:
    """The major and minor numbers of a PEP 440 or SemVer version."""
    parts: list[int] = []
    for piece in text.split(".")[:2]:
        digits = ""
        for character in piece:
            if not character.isdigit():
                break
            digits += character
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts)


def compatible_sdk(sdk_version: str) -> bool:
    """The npm package shares the Python package's major and minor version."""
    try:
        installed = version("gazua")
    except PackageNotFoundError:
        return True
    return base_version(sdk_version) == base_version(installed)


@contextmanager
def started_runner(
    config: GazuaConfig,
    project_root: Path,
    session: Path,
    operation: str,
    deadline: float,
    expected_hash: str | None = None,
) -> Generator[tuple[RunnerProcess, RunnerReady, TypeScriptProvenance]]:
    """A runner that loaded the module and described its tools, closed on exit."""
    from gazua.typescript.policy import check_module, module_sha256, node_executable

    target = config.typescript
    if target is None:
        raise TypeScriptRunBlocked("typescript_target_missing")
    try:
        node = node_executable()
        path = check_module(project_root, target.module)
    except ConfigError as error:
        raise TypeScriptRunBlocked(error.diagnostics[0].code) from None
    digest = module_sha256(path)
    if expected_hash is not None and digest != expected_hash:
        raise TypeScriptRunBlocked("typescript_module_changed")
    process = RunnerProcess(node, project_root, session)
    try:
        process.start()
        opened = process.request(
            RunnerOpen(
                protocol_version=PROTOCOL_VERSION,
                type="open",
                request_id="1",
                operation="run" if operation == "run" else "describe",
                module=target.module,
                exports=_exports(config),
            ),
            RunnerReady,
            deadline=deadline,
        )
        if isinstance(opened, RunnerError):
            raise TypeScriptRunBlocked(failure_code(opened.code))
        if not compatible_sdk(opened.sdk_version):
            raise TypeScriptRunBlocked("typescript_package_incompatible")
        provenance = TypeScriptProvenance(
            protocol_version=PROTOCOL_VERSION,
            sdk_version=opened.sdk_version,
            node_version=opened.node_version,
            module_sha256=digest,
        )
        yield process, opened, provenance
    except RunnerFailed as failed:
        raise TypeScriptRunBlocked(failure_code(failed.code)) from None
    finally:
        process.close()


class TypeScriptSender:
    """Delivers turns to the runner; at most one injection is armed for the next turn."""

    def __init__(self, process: RunnerProcess, deadline: float) -> None:
        self.process = process
        self.deadline = deadline
        self._armed: str | None = None

    @contextmanager
    def armed(self, injection_id: str) -> Generator[None]:
        self._armed = injection_id
        try:
            yield
        finally:
            self._armed = None

    def __call__(self, message: str) -> str:
        from gazua.runtime.hooks import AuthenticationFailed, HookError, RateLimited

        try:
            answer = self.process.request(
                RunnerInvoke(
                    protocol_version=PROTOCOL_VERSION,
                    type="invoke",
                    request_id="1",
                    message=message,
                    armed_injection_id=self._armed,
                ),
                RunnerResult,
                deadline=self.deadline,
            )
        except RunnerFailed as failed:
            raise TypeScriptRunBlocked(failure_code(failed.code)) from None
        if isinstance(answer, RunnerResult):
            return answer.response
        if answer.code == "rate_limited":
            raise RateLimited("entrypoint", answer.retry_after)
        if answer.code == "agent_authentication_failed":
            raise AuthenticationFailed(
                "entrypoint", "The agent reported an authentication failure."
            )
        if answer.code in ("entrypoint_error", "response_not_text"):
            raise HookError("entrypoint", "The entrypoint failed.", answer.error_type or "Error")
        if answer.code == "blocked":
            raise GazuaBlockedError("tool_blocked")
        raise TypeScriptRunBlocked(failure_code(answer.code))

    def sink(self, value: JsonValue) -> dict[str, Any]:
        from gazua.runtime.hooks import SinkError, SinkResultInvalid

        try:
            answer = self.process.request(
                RunnerSink(
                    protocol_version=PROTOCOL_VERSION, type="sink", request_id="1", value=value
                ),
                RunnerSinkResult,
                deadline=self.deadline,
            )
        except RunnerFailed as failed:
            raise TypeScriptRunBlocked(failure_code(failed.code)) from None
        if isinstance(answer, RunnerSinkResult):
            return {"effect": answer.effect, "proof": dict(answer.proof)}
        if answer.code == "sink_result_invalid":
            raise SinkResultInvalid("output_sink", "The result needs exactly effect and proof.")
        raise SinkError("output_sink", "The output sink failed.", answer.error_type)

    def reset(self) -> None:
        from gazua.runtime.hooks import ResetFailed

        try:
            answer = self.process.request(
                RunnerReset(protocol_version=PROTOCOL_VERSION, type="reset", request_id="1"),
                RunnerResetDone,
                deadline=self.deadline,
            )
        except RunnerFailed as failed:
            raise TypeScriptRunBlocked(failure_code(failed.code)) from None
        if isinstance(answer, RunnerError):
            if answer.code == "reset_error":
                raise ResetFailed("target.reset", "The reset export failed.", answer.error_type)
            raise TypeScriptRunBlocked(failure_code(answer.code))


def execute(request: Mapping[str, Any], context: ExecutionContext) -> dict[str, Any]:
    """Runs one agent attack or legitimate task through this attempt's Node runner."""
    from gazua.modes.agent_executor import dispatch

    config: GazuaConfig = context.config
    deadline = _deadline(context)
    payload: Mapping[str, Any] = request["payload"]
    expected = payload.get(HASH_FIELD)
    with started_runner(
        config,
        Path.cwd(),
        context.session_path,
        "run",
        deadline,
        expected if isinstance(expected, str) else None,
    ) as (process, _, _):
        sender = TypeScriptSender(process, deadline)
        target = config.typescript
        if target is not None and target.reset_export is not None:
            # The reset runs in this attempt's runner, before its first turn, as F05 requires.
            sender.reset()
        sink = sender.sink if target is not None and target.output_sink_export else None
        return dispatch(request, context, sender, sink=sink, arm=sender.armed)


def describe(
    config: GazuaConfig, project_root: Path, session: Path, timeout: float
) -> dict[str, Any]:
    """The target's tools and runtime, read from a runner that never calls the entrypoint."""
    deadline = time.monotonic() + timeout - DEADLINE_MARGIN
    with started_runner(config, project_root, session, "describe", deadline) as (_, ready, origin):
        found = {tool.name: tool for tool in ready.tools}
    names = sorted(set(config.tools) | set(found))
    tools: list[dict[str, Any]] = []
    for name in names:
        declaration = config.tools.get(name)
        registered = found.get(name)
        tools.append(
            {
                "name": name,
                "registered": registered is not None,
                "safe": declaration is not None and declaration.safe,
                "classified": declaration is not None
                and declaration.classification.value != "unclassified",
                "ambiguous": registered is not None and registered.ambiguous,
                "signature_available": False,
                "supports_sync": registered is not None and registered.supports_sync,
                "supports_async": registered is not None and registered.supports_async,
                "diagnostics": ["tool_name_conflict"]
                if registered is not None and registered.ambiguous
                else [],
            }
        )
    return {"complete": True, "tools": tools, "typescript": origin.model_dump(mode="json")}


def final_reset(
    config: GazuaConfig, project_root: Path, session: Path, timeout: float
) -> dict[str, Any]:
    """Runs the reset export once more in its own runner, after every attempt."""
    from gazua.runtime.hooks import ResetFailed

    if config.typescript is None or config.typescript.reset_export is None:
        return {"status": "ok", "reset": "absent"}
    deadline = time.monotonic() + timeout - DEADLINE_MARGIN
    try:
        with started_runner(config, project_root, session, "run", deadline) as (process, _, _):
            TypeScriptSender(process, deadline).reset()
    except (ResetFailed, TypeScriptRunBlocked):
        return {"status": "reset_failed"}
    return {"status": "ok", "reset": "succeeded"}


__all__ = [
    "TypeScriptRunBlocked",
    "TypeScriptSender",
    "base_version",
    "compatible_sdk",
    "describe",
    "execute",
    "failure_code",
    "final_reset",
    "started_runner",
]
