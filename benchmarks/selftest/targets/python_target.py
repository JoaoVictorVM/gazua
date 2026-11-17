"""The benchmark's target in plain Python, registered with ``gazua.wrap``.

The benchmark copies this package into each cell's workspace with ``domain.json`` and a
``profile.json``. The profile is read once, at import, before any tool is registered, so the
inventory, the declarations in gazua.yaml and the callable tools always agree. Every real call
is recorded by the spy; tools mode never calls the entrypoint.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final

import gazua

from .domain import DomainData, Profile, Store, exposed_tools
from .spy import effect, install

install()

DOMAIN_FILE: Final = Path(__file__).with_name("domain.json")
DATA: Final = DomainData.load(DOMAIN_FILE)
PROFILE: Final = Profile.read(Path.cwd())

_store = Store(DATA, PROFILE)


def get_order(order_id: str, user_id: str | None = None, actor: str | None = None) -> Any:
    effect("get_order", actor=actor)
    return _store.get_order(order_id, actor)


async def get_invoice(invoice_id: int, user_id: str | None = None, actor: str | None = None) -> Any:
    effect("get_invoice", actor=actor)
    return _store.get_invoice(invoice_id, actor)


def get_note(note_id: str, user_id: str | None = None, actor: str | None = None) -> Any:
    effect("get_note", actor=actor)
    return _store.get_note(note_id, actor)


def delete_account(user_id: str = "self", actor: str | None = None) -> Any:
    effect("delete_account", actor=actor)
    return _store.delete_account(user_id)


def notify_partner(order_id: str = "", message: str = "") -> Any:
    effect("notify_partner")
    return {"queued": True, "dry_run": False}


def refund(
    order_id: str = "order-attacker-1", amount_cents: int = 100, actor: str | None = None
) -> Any:
    effect("refund", actor=actor)
    done = _store.refund(order_id, amount_cents)
    # A released tool calling one that is not: the inner call must stay in dry-run.
    TOOLS["notify_partner"](order_id=order_id, message="refund issued")
    return done


_FUNCTIONS: Final = {
    "get_order": get_order,
    "get_invoice": get_invoice,
    "get_note": get_note,
    "delete_account": delete_account,
    "refund": refund,
    "notify_partner": notify_partner,
}

TOOLS: Final[dict[str, Any]] = (
    gazua.wrap({name: _FUNCTIONS[name] for name in exposed_tools(PROFILE)})
    if exposed_tools(PROFILE)
    else {}
)


def entrypoint(message: str) -> str:
    effect("entrypoint_called")
    raise RuntimeError("the agent entrypoint is not available in this target")


def reset() -> None:
    global _store
    effect("reset")
    _store = Store(DATA, PROFILE)


def sink(value: Any) -> dict[str, Any]:
    effect("sink")
    return _store.output(value)
