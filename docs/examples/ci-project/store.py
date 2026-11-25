"""A small store whose order tool checks the caller, used to exercise the Action.

It only uses the standard library, because the Action runs the target in its own environment.
"""

from typing import Any

import gazua

ORDERS = {
    "order-victim-1": {"order_id": "order-victim-1", "user_id": "victim-1"},
    "order-attacker-1": {"order_id": "order-attacker-1", "user_id": "attacker-1"},
}


def get_order(order_id: str, user_id: str | None = None, actor: str | None = None) -> Any:
    order = ORDERS.get(order_id)
    if order is None or order["user_id"] != actor:
        return None
    return dict(order)


TOOLS = gazua.wrap({"get_order": get_order})


def entrypoint(message: str) -> str:
    raise RuntimeError("tools mode never calls the entrypoint")
