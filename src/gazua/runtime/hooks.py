"""Calls the target's ``entrypoint`` and ``target.reset``.

Both are imported only when called, through ``resolve_reference``, the one place allowed to
import the target. Errors name the exception class and never its message, which can quote the
target's data.
"""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable
from typing import Any

from gazua.config.references import resolve_reference
from gazua.diagnostics import ConfigError, Diagnostic
from gazua.integration.telemetry import GazuaRateLimited

_resolved: dict[tuple[str, str], Callable[..., Any]] = {}


class HookError(Exception):
    """A target hook could not run or returned something unusable."""

    code = "entrypoint_error"

    def __init__(self, hook: str, reason: str) -> None:
        self.hook = hook
        self.reason = reason
        super().__init__(f"{hook}: {reason}")

    @property
    def diagnostic(self) -> Diagnostic:
        return Diagnostic(code=self.code, field=self.hook, message=self.reason)


class ResetFailed(HookError):
    """``target.reset`` failed. Attacks that depend on a clean state are not tested."""

    code = "reset_error"


class RateLimited(HookError):
    """The entrypoint raised ``GazuaRateLimited``. The target's message is never kept."""

    code = "rate_limited"

    def __init__(self, hook: str, retry_after: float | None) -> None:
        self.retry_after = retry_after
        super().__init__(hook, "The target reported a rate limit (429).")


def _resolve(reference: str, hook: str, error: type[HookError]) -> Callable[..., Any]:
    key = (hook, reference)
    found = _resolved.get(key)
    if found is None:
        try:
            found = resolve_reference(reference, hook)
        except ConfigError as failure:
            raise error(hook, failure.diagnostics[0].message) from None
        _resolved[key] = found
    return found


async def _wait(awaitable: Awaitable[Any]) -> Any:
    return await awaitable


def _call(
    function: Callable[..., Any],
    hook: str,
    error: type[HookError],
    *args: Any,
    rate_limits: bool = False,
) -> Any:
    try:
        result = function(*args)
        if inspect.isawaitable(result):
            result = asyncio.run(_wait(result))
    except GazuaRateLimited as signal:
        if not rate_limits:
            raise error(hook, f"The call raised {type(signal).__name__}.") from None
        raise RateLimited(hook, signal.retry_after) from None
    # Hooks are the target's code; any failure, even SystemExit, is reported, not propagated.
    except (Exception, SystemExit) as failure:  # noqa: BLE001
        raise error(hook, f"The call raised {type(failure).__name__}.") from None
    return result


def call_entrypoint(reference: str, message: str) -> str:
    """Sends one message to the agent and returns its text response.

    A ``GazuaRateLimited`` raised by the entrypoint becomes ``RateLimited``; any other failure
    is a ``HookError`` that names only the exception class.
    """
    entrypoint = _resolve(reference, "entrypoint", HookError)
    response = _call(entrypoint, "entrypoint", HookError, message, rate_limits=True)
    if not isinstance(response, str):
        raise HookError("entrypoint", f"The response is {type(response).__name__}, expected str.")
    return response


def call_reset(reference: str | None) -> bool:
    """Runs ``target.reset``. Returns False when none is declared."""
    if reference is None:
        return False
    reset = _resolve(reference, "target.reset", ResetFailed)
    _call(reset, "target.reset", ResetFailed)
    return True


def clear_resolved_hooks() -> None:
    _resolved.clear()
