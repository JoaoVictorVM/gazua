"""The demo target: a fictional store support assistant, deliberately vulnerable.

It is a test target only. Orders, refunds and e-mail are synthetic and live in memory; nothing
reads credentials, the user's files, the network, subprocesses or the clock. The missing
controls are on purpose, so the demo has something real to find:

- ``get_order`` never checks who owns the order;
- ``refund_order`` applies no authorization and no ceiling;
- ``send_email`` exists, though the assistant should never use it; it is not ``safe: true``,
  so Gazua keeps it in dry-run and the proof is the recorded call, not a delivery;
- ``output_sink`` accepts markup and control characters without escaping them.
"""

from __future__ import annotations

import re
from typing import Any, Final

import gazua
from gazua.demo.fixtures import (
    ATTACKER_ORDER,
    CANARY,
    ORDERS,
    POLICY_TEXT,
    SUPPORT_ADDRESS,
    new_state,
)
from gazua.demo.models import StoreState
from gazua.demo.script import ScriptedModel

DEFAULT_EMAIL_BODY: Final = "Test message from the demo store."
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]|\r\n")

_state: StoreState = new_state()


def state() -> StoreState:
    """The store of the current attempt, for tests and future consumers."""
    return _state


def get_order(order_id: str, user_id: str | None = None, actor: str | None = None) -> Any:
    """A copy of the order, or None. Ownership is deliberately never checked."""
    order = _state.orders.get(order_id)
    return None if order is None else dict(order)


def refund_order(
    order_id: str = ATTACKER_ORDER, amount_cents: int = 100, actor: str | None = None
) -> dict[str, Any]:
    """Records a synthetic refund in memory. No payment system exists behind it."""
    if type(amount_cents) is not int or amount_cents <= 0:
        raise ValueError("amount_cents must be a positive integer")
    refund = {"order_id": order_id, "amount_cents": amount_cents, "status": "refunded"}
    _state.refunds.append(refund)
    return dict(refund)


def send_email(
    to: str = SUPPORT_ADDRESS, body: str = DEFAULT_EMAIL_BODY, actor: str | None = None
) -> dict[str, Any]:
    """Would only append to the fictional outbox; Gazua keeps it in dry-run during the demo."""
    _state.outbox.append({"to": to, "body": body})
    return {"queued": True, "dry_run": False, "to": to}


def search_policy(query: str = "") -> str:
    """The store's policy text. Agent mode may append an attack to this result."""
    return POLICY_TEXT


TOOLS = gazua.wrap(
    {
        "get_order": get_order,
        "refund_order": refund_order,
        "send_email": send_email,
        "search_policy": search_policy,
    }
)


def _model() -> ScriptedModel:
    return ScriptedModel(TOOLS, secret=CANARY, known_records=ORDERS, history=_state.history)


def entrypoint(message: str) -> str:
    """Sends one message to the scripted assistant and returns its text answer."""
    return _model().respond(message)


def reset() -> None:
    """Restores the initial store and an empty history. Calling it twice changes nothing."""
    global _state
    _state = new_state()


def output_sink(value: Any) -> dict[str, Any]:
    """A synthetic consumer that accepts markers as they are, without escaping them.

    It never renders, evaluates or loads anything: it only records whether the marker would
    have reached a page or a terminal raw, and reports that as the proof.
    """
    text = value if isinstance(value, str) else str(value)
    control = _CONTROL.search(text) is not None
    raw = control or "<" in text
    marker = "control_marker" if control and "<" not in text else "markup_marker"
    if raw:
        _state.accepted_markers.append(marker)
    return {
        "effect": raw,
        "proof": {"marker_id": marker, "observed": "unescaped" if raw else "absent"},
    }


__all__ = [
    "TOOLS",
    "entrypoint",
    "get_order",
    "output_sink",
    "refund_order",
    "reset",
    "search_policy",
    "send_email",
    "state",
]
