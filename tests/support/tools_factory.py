"""Configurations, inventories and catalog selections for tools mode tests.

Inventories are built the way discovery describes them, from real function signatures, so a
plan test sees the same data the supervisor gets from the worker.
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from functools import cache
from typing import Any

from gazua.catalog.loader import load_catalog
from gazua.catalog.models import Mold
from gazua.catalog.selection import select_molds
from gazua.config.models import GazuaConfig
from gazua.integration.registry import RegisteredTool
from gazua.modes.tools_models import ToolsInventory
from gazua.runtime.tools import ToolInventory

ATTACKER = "attacker-1"
VICTIM = "victim-1"
CANARY = "GAZUA-CANARY-7f3a9c"
SECOND_CANARY = "GAZUA-CANARY-second-41b2"


def delete_account(user_id: str = "self", actor: str | None = None) -> str:
    return "deleted"


def refund(amount: int = 1, actor: str | None = None) -> str:
    return "refunded"


def get_order(order_id: str, user_id: str | None = None, actor: str | None = None) -> Any:
    return None


def get_invoice(invoice_id: int, user_id: str | None = None, actor: str | None = None) -> Any:
    return None


def send_email(to: str = "x", actor: str | None = None) -> str:
    return "sent"


FUNCTIONS: dict[str, Callable[..., Any]] = {
    "delete_account": delete_account,
    "refund": refund,
    "get_order": get_order,
    "get_invoice": get_invoice,
    "send_email": send_email,
}

BASE: dict[str, Any] = {
    "schema_version": 1,
    "entrypoint": "tools_target:entrypoint",
    "tools": {
        "delete_account": {"safe": True, "forbidden": True, "actor_arg": "actor"},
        "refund": {"safe": True, "sensitive": True, "actor_arg": "actor"},
        "get_order": {
            "safe": True,
            "sensitive": False,
            "owner_arg": "user_id",
            "actor_arg": "actor",
        },
        "get_invoice": {
            "safe": True,
            "sensitive": False,
            "owner_arg": "user_id",
            "actor_arg": "actor",
        },
        "send_email": {"sensitive": True, "actor_arg": "actor"},
    },
    "fixtures": {
        "attacker": {"id": ATTACKER},
        "victim": {
            "id": VICTIM,
            "records": [
                {"tool": "get_order", "id_arg": "order_id", "id": "order-victim-1"},
                {"tool": "get_invoice", "id_arg": "invoice_id", "id": 7},
                {"tool": "get_order", "id_arg": "order_id", "id": "order-victim-2"},
            ],
        },
    },
    "canaries": [CANARY, SECOND_CANARY],
    "output_sink": "tools_target:sink",
}


def config_document(**overrides: Any) -> dict[str, Any]:
    document = copy.deepcopy(BASE)
    document.update(overrides)
    return document


def config(**overrides: Any) -> GazuaConfig:
    return GazuaConfig.model_validate(config_document(**overrides))


def inventory(
    configuration: GazuaConfig,
    functions: Mapping[str, Callable[..., Any]] | None = None,
    *,
    ambiguous: tuple[str, ...] = (),
    complete: bool = True,
) -> ToolsInventory:
    """The description discovery would return for these registered functions."""
    chosen = FUNCTIONS if functions is None else functions
    registered: dict[str, tuple[RegisteredTool, ...]] = {
        name: (RegisteredTool(name, [function], proxy=function),)
        for name, function in chosen.items()
    }
    for name in ambiguous:
        registered[name] = (*registered[name], RegisteredTool(name, [send_email], proxy=send_email))
    document = ToolInventory.collect(configuration, registered).describe()
    return ToolsInventory.model_validate({**document, "complete": complete})


@cache
def tools_molds() -> tuple[Mold, ...]:
    return tuple(entry.mold for entry in select_molds(load_catalog().entries, "tools"))


def mold(mold_id: str) -> Mold:
    return next(item for item in tools_molds() if item.id == mold_id)
