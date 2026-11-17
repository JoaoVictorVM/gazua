"""The benchmark's target in plain Python, registered with ``gazua.wrap``.

The benchmark copies this package into each cell's workspace with ``domain.json`` and a
``profile.json``. The profile is read once, at import, before any tool is registered, so the
inventory, the declarations in gazua.yaml and the callable tools always agree. Every real call
is recorded by the spy; tools mode never calls the entrypoint.

In agent mode the entrypoint runs the simulated model. The model asks the target's dispatcher
for a tool by name; the dispatcher applies the deployment's controls before the wrapped tool
runs, the way an application decides which actions its assistant may take.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final

import gazua

from .domain import DomainData, Profile, Store, exposed_tools
from .scripted import ScriptedModel
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
    if "notify_partner" in TOOLS:
        TOOLS["notify_partner"](order_id=order_id, message="refund issued")
    return done


def search_docs(query: str = "") -> Any:
    effect("search_docs")
    return _store.search_docs()


def read_memory() -> Any:
    effect("read_memory")
    return _store.read_memory()


def create_ticket(description: str = "") -> Any:
    effect("create_ticket")
    return _store.create_ticket(description)


def generate_report(actor: str | None = None) -> Any:
    effect("generate_report")
    return _store.generate_report()


_FUNCTIONS: Final = {
    "get_order": get_order,
    "get_invoice": get_invoice,
    "get_note": get_note,
    "delete_account": delete_account,
    "refund": refund,
    "notify_partner": notify_partner,
    "search_docs": search_docs,
    "read_memory": read_memory,
    "create_ticket": create_ticket,
    "generate_report": generate_report,
}

TOOLS: Final[dict[str, Any]] = (
    gazua.wrap({name: _FUNCTIONS[name] for name in exposed_tools(PROFILE)})
    if exposed_tools(PROFILE)
    else {}
)


_history: list[str] = []


def dispatch(name: str, **arguments: Any) -> Any:
    """Runs a tool for the assistant, or returns None when the deployment does not allow it."""
    if name not in TOOLS or not PROFILE.dispatches(name):
        effect("dispatch_refused", tool=name)
        return None
    return TOOLS[name](**arguments)


def entrypoint(message: str) -> str:
    effect("entrypoint_called")
    model = ScriptedModel(
        dispatch,
        TOOLS,
        context=_store.assistant_context(),
        known_records=DATA.orders,
        history=_history,
    )
    return model.respond(message)


def reset() -> None:
    global _store
    effect("reset")
    _store = Store(DATA, PROFILE)
    _history.clear()


def sink(value: Any) -> dict[str, Any]:
    effect("sink")
    return _store.output(value)
