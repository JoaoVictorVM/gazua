"""Delivery of attack text through tool results.

The text is appended as data. Nothing here interprets it, and a result that is not text is
left untouched, recorded as not delivered so the attack can be reported as not tested.

An executor that sends several turns arms one injection at a time inside its own worker, so
each turn reaches exactly the call that follows its message. While an injection is armed no
other one is chosen; sessions used without arming keep the first pending injection per tool.
"""

from __future__ import annotations

import threading
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from gazua.integration.session import Injection, Session

_lock = threading.Lock()
_deliveries: dict[tuple[str, str], int] = {}
_armed: list[str] = []


def _pending(session: Session, tool: str) -> Injection | None:
    armed = _armed[-1] if _armed else None
    for injection in session.injections:
        if injection.tool != tool or (armed is not None and injection.id != armed):
            continue
        if _deliveries.get((session.run_id, injection.id), 0) < injection.max_deliveries:
            return injection
    return None


@contextmanager
def armed_turn(injection_id: str) -> Generator[None]:
    """Only the injection ``injection_id`` of the session can be delivered inside this block.

    For Gazua's executors inside a supervised worker; the session file is never changed.
    """
    with _lock:
        _armed.append(injection_id)
    try:
        yield
    finally:
        with _lock:
            _armed.remove(injection_id)


def inject(session: Session, tool: str, result: object) -> tuple[Any, dict[str, Any] | None]:
    """The result with the pending injection for this tool, and what goes to the log."""
    with _lock:
        injection = _pending(session, tool)
        if injection is None:
            return result, None
        if not isinstance(result, str):
            return result, {
                "id": injection.id,
                "delivered": False,
                "reason": "unsupported_result_type",
            }
        key = (session.run_id, injection.id)
        _deliveries[key] = _deliveries.get(key, 0) + 1
    return f"{result}\n{injection.text}", {"id": injection.id, "delivered": True, "reason": None}


def reset_deliveries() -> None:
    with _lock:
        _deliveries.clear()
        _armed.clear()
