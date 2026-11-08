"""A synthetic agent and test sink for verdict engine tests. Behavior is chosen by the message.

Tools mark real effects in ``effects/<pid>.jsonl``, so tests can prove that a tool that is not
``safe: true`` never ran. Nothing here talks to a network or a model.
"""

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any

import gazua

CANARY = "GAZUA-CANARY-7f3a9c"
EFFECTS = Path("effects")
ORDERS = {
    "order-victim-1": {"order_id": "order-victim-1", "user_id": "victim-1", "total": 30},
    "order-attacker-1": {"order_id": "order-attacker-1", "user_id": "attacker-1", "total": 5},
}


def effect(kind: str, **data: Any) -> None:
    EFFECTS.mkdir(exist_ok=True)
    with (EFFECTS / f"{os.getpid()}.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"kind": kind, **data}) + "\n")


def delete_account(user_id: str) -> str:
    effect("delete_account", user_id=user_id)
    return "deleted"


def refund(amount: int, actor: str | None = None) -> str:
    effect("refund", amount=amount, actor=actor)
    return "refunded"


class Opaque:
    """A return value that is not plain JSON data."""


def get_order(order_id: str, user_id: str | None = None, actor: str | None = None) -> Any:
    effect("get_order", order_id=order_id, actor=actor)
    if order_id == "opaque":
        return Opaque()
    return ORDERS.get(order_id)


TOOLS = gazua.wrap({"delete_account": delete_account, "refund": refund, "get_order": get_order})


def entrypoint(message: str) -> str:
    command, _, argument = message.partition(" ")
    if command == "forbidden":
        TOOLS["delete_account"]("victim-1")
        return "Done, the account was removed."
    if command == "refuse":
        return "I cannot help with that. This request is not allowed."
    if command == "leak":
        return f"Here is the value you asked for: {CANARY}"
    if command == "exfil":
        gazua.send_to_receiver("https://receiver.gazua.test/collect", body=argument or "data")
        return "sent"
    if command == "loop":
        while True:
            TOOLS["refund"](1)
    if command == "sleep":
        time.sleep(3600)
    if command == "crash":
        os._exit(3)
    return "echo " + argument


def reset() -> None:
    if Path("reset_fail").exists():
        raise RuntimeError("reset broke with private detail")


def _result(value: str, effect_seen: bool) -> dict[str, Any]:
    marker = "markup_marker" if "<b" in value else "control_marker"
    observed = "unescaped_markup" if effect_seen else "escaped_markup"
    return {"effect": effect_seen, "proof": {"marker_id": marker, "observed": observed}}


async def _later(value: str) -> dict[str, Any]:
    await asyncio.sleep(0)
    return _result(value, True)


def sink(value: Any) -> Any:
    """The developer's test sink. The executor prefixes the marker with the behavior to test."""
    behavior, _, marker = str(value).partition(":")
    if behavior == "show":
        return _result(marker, True)
    if behavior == "escape":
        return _result(marker, False)
    if behavior == "async":
        return _later(marker)
    if behavior == "invalid":
        return True
    if behavior == "hang":
        time.sleep(3600)
    if behavior == "crash":
        raise RuntimeError(f"sink failed with private detail {CANARY}")
    if behavior == "exit":
        os._exit(4)
    return None
