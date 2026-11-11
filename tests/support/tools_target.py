"""A synthetic store for tools mode tests. A ``hardened`` file in the project switches modes.

Vulnerable mode returns any order to anyone and echoes the canary note; hardened mode checks
the actor and escapes the sink. Every real effect goes to ``effects/<pid>.jsonl``, so tests can
prove that a tool that is not ``safe: true`` never ran and that the entrypoint is never called.
Once imported, the module also records credential reads and network attempts in the worker.
"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import gazua

CANARY = "GAZUA-CANARY-7f3a9c"
EFFECTS = Path("effects")
ORDERS = {
    "order-victim-1": {"order_id": "order-victim-1", "user_id": "victim-1", "note": CANARY},
    "order-attacker-1": {"order_id": "order-attacker-1", "user_id": "attacker-1", "note": "-"},
}
CREDENTIAL_SUFFIXES = ("_API_KEY", "_TOKEN", "_SECRET", "_PASSWORD")


def effect(kind: str, **data: Any) -> None:
    EFFECTS.mkdir(exist_ok=True)
    with (EFFECTS / f"{os.getpid()}.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"kind": kind, **data}) + "\n")


def hardened() -> bool:
    return Path("hardened").exists()


class _Watched(type(os.environ)):
    def __getitem__(self, key: str) -> str:
        if key.upper().endswith(CREDENTIAL_SUFFIXES):
            effect("credential_read", name=key)
        return super().__getitem__(key)


def _audit(event: str, args: tuple[object, ...]) -> None:
    if event.startswith(("socket.", "http.", "urllib.")):
        effect("network", event=event)


os.environ.__class__ = _Watched
sys.addaudithook(_audit)


def get_order(order_id: str, user_id: str | None = None, actor: str | None = None) -> Any:
    effect("get_order", order_id=order_id, actor=actor)
    if Path("slow").exists():
        time.sleep(3600)
    order = ORDERS.get(order_id)
    if order is None or (hardened() and order["user_id"] != actor):
        return None
    return dict(order)


def refund(amount: int = 1, actor: str | None = None) -> str:
    effect("refund", amount=amount, actor=actor)
    if hardened() and actor is None:
        raise PermissionError("refunds need an authenticated actor")
    return "refunded"


def delete_account(user_id: str = "self") -> str:
    effect("delete_account", user_id=user_id)
    return "deleted"


async def archive_order(order_id: str = "order-attacker-1") -> str:
    effect("archive_order", order_id=order_id)
    return "archived"


@gazua.tool
def send_email(to: str = "victim@example.test") -> str:
    effect("send_email", to=to)
    return "sent"


TOOLS = gazua.wrap(
    {
        "get_order": get_order,
        "refund": refund,
        "delete_account": delete_account,
        "archive_order": archive_order,
    }
)


def entrypoint(message: str) -> str:
    effect("entrypoint_called")
    raise RuntimeError("tools mode must never call the entrypoint")


def reset() -> None:
    effect("reset")
    if Path("reset_fail").exists():
        raise RuntimeError("reset failed with private detail")


def _sink_result(value: Any) -> dict[str, Any]:
    shown = not hardened()
    marker = "markup_marker" if "<b" in str(value) else "control_marker"
    return {
        "effect": shown,
        "proof": {"marker_id": marker, "observed": "unescaped" if shown else "escaped"},
    }


async def _later(value: Any) -> dict[str, Any]:
    await asyncio.sleep(0)
    return _sink_result(value)


def sink(value: Any) -> Any:
    effect("sink", value=str(value))
    if Path("broken_sink").exists():
        raise RuntimeError(f"sink failed with private detail {CANARY}")
    if Path("async_sink").exists():
        return _later(value)
    return _sink_result(value)
