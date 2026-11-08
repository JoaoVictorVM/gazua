"""Tool call ceiling of one supervised execution, enforced before the call has any effect.

A slot is reserved under a lock shared by every thread of the process, before identity, the
tool or its dry-run value. The call that reaches the ceiling is admitted and announced to the
supervisor first; every later call is refused without changing the count, even when the target
catches the error and keeps trying. Sessions without an execution channel keep the previous
behavior, with no ceiling here.
"""

from __future__ import annotations

import threading

from gazua.integration.channel import ChannelError, channel_for
from gazua.integration.errors import GazuaBlockedError
from gazua.integration.session import Session

CEILING_REASON = "tool_call_ceiling"

_lock = threading.Lock()
_admitted: dict[str, int] = {}
_latched: set[str] = set()


def admit(session: Session) -> None:
    """Reserves one tool call slot or raises ``GazuaBlockedError``."""
    execution = session.execution
    if execution is None:
        return
    key = execution.execution_id
    with _lock:
        if key in _latched:
            raise GazuaBlockedError(CEILING_REASON)
        count = _admitted.get(key, 0) + 1
        reached = count >= execution.max_tool_calls
        channel = channel_for(execution)
        try:
            channel.emit("tool_call_admitted", {"count": count}, sync=reached)
            if reached:
                channel.emit(CEILING_REASON, {"count": count}, sync=True)
        except ChannelError:
            raise GazuaBlockedError("execution_channel_unavailable") from None
        _admitted[key] = count
        if reached:
            _latched.add(key)


def admitted_calls(execution_id: str) -> int:
    with _lock:
        return _admitted.get(execution_id, 0)


def reset_admissions() -> None:
    with _lock:
        _admitted.clear()
        _latched.clear()
