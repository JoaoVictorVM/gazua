"""Delivery of attack text through tool results.

The text is appended as data. Nothing here interprets it, and a result that is not text is
left untouched, recorded as not delivered so the attack can be reported as not tested.
"""

from __future__ import annotations

import threading
from typing import Any

from gazua.integration.session import Injection, Session

_lock = threading.Lock()
_deliveries: dict[tuple[str, str], int] = {}


def _pending(session: Session, tool: str) -> Injection | None:
    for injection in session.injections:
        if injection.tool != tool:
            continue
        if _deliveries.get((session.run_id, injection.id), 0) < injection.max_deliveries:
            return injection
    return None


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
