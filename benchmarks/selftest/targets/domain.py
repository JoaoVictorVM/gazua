"""The synthetic store every benchmark target shares: data, controls and tool behavior.

Nothing here knows the catalog, a mold, the matrix or an expected result. A profile only says
which controls are on, and it is fixed before any tool is registered. Each control guards one
surface, so turning one off exposes exactly that surface:

- ``*-ownership``: a user-scoped read (an actor is present) returns only the actor's records.
  A call without an actor is a service call, trusted by design; minimization still applies.
- ``note-minimization``: internal fields never leave a note.
- ``forbidden-tool-exposure`` and ``sensitive-operation``: the capability is not registered and
  not declared, so it does not exist for the attacker; a refusal text would still be a call.
- ``output-escaping``: the output sink escapes markup and control characters.
"""

from __future__ import annotations

import copy
import html
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Literal

Variant = Literal["vulnerable", "hardened", "no-tools", "mutant"]

CONTROLS: Final = (
    "order-ownership",
    "invoice-ownership",
    "note-ownership",
    "note-minimization",
    "forbidden-tool-exposure",
    "sensitive-operation",
    "output-escaping",
)
PROFILE_FILE: Final = "profile.json"
INTERNAL_FIELDS: Final = ("internal_note",)
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

# What a user of the store would write in gazua.yaml for each tool.
DECLARATIONS: Final[dict[str, dict[str, Any]]] = {
    "get_order": {"safe": True, "sensitive": False, "owner_arg": "user_id", "actor_arg": "actor"},
    "get_invoice": {
        "safe": True,
        "sensitive": False,
        "owner_arg": "user_id",
        "actor_arg": "actor",
    },
    "get_note": {"safe": True, "sensitive": False, "owner_arg": "user_id", "actor_arg": "actor"},
    "delete_account": {"safe": True, "forbidden": True, "actor_arg": "actor"},
    "refund": {"safe": True, "sensitive": True, "actor_arg": "actor"},
    # Never marked safe: Gazua must keep it in dry-run even when a released tool calls it.
    "notify_partner": {"sensitive": True, "dry_run_return": {"queued": False, "dry_run": True}},
}
RECORD_TOOLS: Final = {"get_order": "order_id", "get_invoice": "invoice_id", "get_note": "note_id"}
_SURFACES: Final = {
    "forbidden-tool-exposure": ("delete_account",),
    "sensitive-operation": ("refund", "notify_partner"),
}


@dataclass(frozen=True, slots=True)
class Profile:
    variant: Variant
    enabled: frozenset[str] = field(default_factory=frozenset[str])

    @classmethod
    def build(cls, variant: Variant, disabled: str | None = None) -> Profile:
        if variant == "vulnerable":
            return cls(variant)
        if (variant == "mutant") != (disabled is not None):
            raise ValueError("a mutant disables exactly one control")
        if disabled is not None and disabled not in CONTROLS:
            raise ValueError("unknown control")
        return cls(variant, frozenset(name for name in CONTROLS if name != disabled))

    def on(self, control: str) -> bool:
        return control in self.enabled

    def document(self) -> dict[str, Any]:
        return {"variant": self.variant, "enabled": sorted(self.enabled)}

    @classmethod
    def read(cls, root: Path) -> Profile:
        document = json.loads((root / PROFILE_FILE).read_text(encoding="utf-8"))
        variant = document["variant"]
        enabled = frozenset(str(name) for name in document["enabled"])
        if variant not in ("vulnerable", "hardened", "no-tools", "mutant") or not (
            enabled <= set(CONTROLS)
        ):
            raise ValueError("invalid profile")
        return cls(variant, enabled)


def exposed_tools(profile: Profile) -> tuple[str, ...]:
    """The tools this profile registers and declares, in name order."""
    if profile.variant == "no-tools":
        return ()
    hidden = {name for control, names in _SURFACES.items() if profile.on(control) for name in names}
    return tuple(sorted(name for name in DECLARATIONS if name not in hidden))


@dataclass(frozen=True, slots=True)
class DomainData:
    attacker: str
    victim: str
    canary: str
    policy: str
    orders: dict[str, dict[str, Any]]
    invoices: dict[int, dict[str, Any]]
    notes: dict[str, dict[str, Any]]
    legitimate: tuple[dict[str, Any], ...]
    plain_output: str

    @classmethod
    def load(cls, path: Path) -> DomainData:
        document = json.loads(path.read_text(encoding="utf-8"))
        if document.get("schema_version") != 1:
            raise ValueError("unknown domain version")
        return cls(
            attacker=document["attacker"],
            victim=document["victim"],
            canary=document["canary"],
            policy=document["policy"],
            orders={item["order_id"]: item for item in document["orders"]},
            invoices={item["invoice_id"]: item for item in document["invoices"]},
            notes={item["note_id"]: item for item in document["notes"]},
            legitimate=tuple(document["legitimate"]),
            plain_output=document["plain_output"],
        )

    def victim_records(self) -> list[dict[str, Any]]:
        """One record of the victim per record tool, in the fixture format of gazua.yaml."""
        found: list[dict[str, Any]] = []
        for tool, id_arg in RECORD_TOOLS.items():
            table = {"get_order": self.orders, "get_invoice": self.invoices, "get_note": self.notes}
            owned = [key for key, item in table[tool].items() if item["user_id"] == self.victim]
            found.append({"tool": tool, "id_arg": id_arg, "id": owned[0]})
        return found


class Store:
    """One attempt's state. Every tool returns copies, so callers cannot change the store."""

    def __init__(self, data: DomainData, profile: Profile) -> None:
        self.data = data
        self.profile = profile
        self.orders = copy.deepcopy(data.orders)
        self.invoices = copy.deepcopy(data.invoices)
        self.notes = copy.deepcopy(data.notes)
        self.refunds: list[dict[str, Any]] = []
        self.deleted: list[str] = []

    def _owned(self, control: str, record: Mapping[str, Any], actor: str | None) -> bool:
        if actor is None or not self.profile.on(control):
            return True
        return record["user_id"] == actor

    def get_order(self, order_id: str, actor: str | None) -> dict[str, Any] | None:
        order = self.orders.get(order_id)
        if order is None or not self._owned("order-ownership", order, actor):
            return None
        return dict(order)

    def get_invoice(self, invoice_id: int | str, actor: str | None) -> dict[str, Any] | None:
        # The lookup accepts a numeric string, as many HTTP layers do; ownership is the guard.
        key = (
            int(invoice_id) if isinstance(invoice_id, str) and invoice_id.isdigit() else invoice_id
        )
        invoice = self.invoices.get(key) if type(key) is int else None
        if invoice is None or not self._owned("invoice-ownership", invoice, actor):
            return None
        return dict(invoice)

    def get_note(self, note_id: str, actor: str | None) -> dict[str, Any] | None:
        note = self.notes.get(note_id)
        if note is None or not self._owned("note-ownership", note, actor):
            return None
        shown = dict(note)
        if self.profile.on("note-minimization"):
            for name in INTERNAL_FIELDS:
                shown.pop(name, None)
        return shown

    def delete_account(self, user_id: str) -> dict[str, Any]:
        self.deleted.append(user_id)
        return {"deleted": user_id}

    def refund(self, order_id: str, amount_cents: int) -> dict[str, Any]:
        if type(amount_cents) is not int or amount_cents <= 0:
            raise ValueError("amount_cents must be a positive integer")
        refund = {"order_id": order_id, "amount_cents": amount_cents, "status": "refunded"}
        self.refunds.append(refund)
        return dict(refund)

    def output(self, value: object) -> dict[str, Any]:
        """Where an answer would be shown. It renders nothing; it reports what arrived raw."""
        text = value if isinstance(value, str) else str(value)
        marker = "markup_marker" if "<" in text else "control_marker"
        if self.profile.on("output-escaping"):
            text = _CONTROL_CHARACTERS.sub("", html.escape(text))
        shown = "<" in text or _CONTROL_CHARACTERS.search(text) is not None
        return {
            "effect": shown,
            "proof": {"marker_id": marker, "observed": "unescaped" if shown else "escaped"},
        }


__all__ = [
    "CONTROLS",
    "DECLARATIONS",
    "PROFILE_FILE",
    "RECORD_TOOLS",
    "DomainData",
    "Profile",
    "Store",
    "Variant",
    "exposed_tools",
]
