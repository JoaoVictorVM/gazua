from pathlib import Path

import pytest
from benchmarks.selftest.targets.domain import (
    CONTROLS,
    DECLARATIONS,
    DomainData,
    Profile,
    Store,
    exposed_tools,
)

DOMAIN = Path(__file__).resolve().parents[2] / "benchmarks/selftest/fixtures/domain.json"


@pytest.fixture(scope="module")
def data() -> DomainData:
    return DomainData.load(DOMAIN)


def test_profiles_disable_exactly_one_control() -> None:
    assert Profile.build("vulnerable").enabled == frozenset()
    assert Profile.build("hardened").enabled == frozenset(CONTROLS)
    for control in CONTROLS:
        assert Profile.build("mutant", control).enabled == frozenset(CONTROLS) - {control}
    with pytest.raises(ValueError, match="exactly one"):
        Profile.build("mutant")
    with pytest.raises(ValueError, match="exactly one"):
        Profile.build("hardened", "order-ownership")
    with pytest.raises(ValueError, match="unknown control"):
        Profile.build("mutant", "no-such-control")


def test_surface_removal_changes_registration_and_declaration() -> None:
    assert exposed_tools(Profile.build("vulnerable")) == tuple(sorted(DECLARATIONS))
    assert exposed_tools(Profile.build("hardened")) == ("get_invoice", "get_note", "get_order")
    assert exposed_tools(Profile.build("no-tools")) == ()
    assert "delete_account" in exposed_tools(Profile.build("mutant", "forbidden-tool-exposure"))
    exposed = exposed_tools(Profile.build("mutant", "sensitive-operation"))
    assert {"refund", "notify_partner"} <= set(exposed)
    assert "delete_account" not in exposed
    assert DECLARATIONS["notify_partner"].get("safe") is not True


def test_legitimate_tasks_still_work_on_the_hardened_store(data: DomainData) -> None:
    store = Store(data, Profile.build("hardened"))
    for task in data.legitimate:
        tool = task["tool"]
        arguments = task["arguments"]
        identifier = arguments[
            {"get_order": "order_id", "get_invoice": "invoice_id"}.get(tool, "note_id")
        ]
        result = getattr(store, tool)(identifier, task["actor"])
        assert result is not None, task["id"]
        for name, value in task["expect"].items():
            assert result[name] == value, task["id"]
    assert store.output(data.plain_output)["effect"] is False


def test_controls_guard_their_own_surface(data: DomainData) -> None:
    hardened = Store(data, Profile.build("hardened"))
    vulnerable = Store(data, Profile.build("vulnerable"))
    victim_note = "note-victim-1"

    assert hardened.get_order("order-victim-1", data.attacker) is None
    assert hardened.get_invoice("7", data.attacker) is None
    assert vulnerable.get_invoice("7", data.attacker) == data.invoices[7]
    assert hardened.get_note(victim_note, data.attacker) is None
    assert "internal_note" not in (hardened.get_note(victim_note, None) or {})
    assert vulnerable.get_note(victim_note, None)["internal_note"] == data.canary  # type: ignore[index]

    marker = '<b data-gazua="marker">X</b>'
    assert hardened.output(marker)["effect"] is False
    assert hardened.output("X\r\nY\x1b[0m")["effect"] is False
    assert vulnerable.output(marker)["effect"] is True
    assert vulnerable.output("X\r\nY")["effect"] is True


def test_store_copies_never_leak_state(data: DomainData) -> None:
    store = Store(data, Profile.build("vulnerable"))
    order = store.get_order("order-victim-1", None)
    assert order is not None
    order["user_id"] = "changed"
    assert store.get_order("order-victim-1", None)["user_id"] == data.victim  # type: ignore[index]
    with pytest.raises(ValueError, match="positive"):
        store.refund("order-attacker-1", 0)
