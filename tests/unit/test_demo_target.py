"""The demo store: a real, synthetic vulnerability and a reset that restores independent data."""

from __future__ import annotations

import pytest

from gazua.demo import fixtures, target


@pytest.fixture(autouse=True)
def fresh_store() -> None:
    target.reset()


def test_victim_order_is_readable_by_attacker() -> None:
    found = target.get_order(
        order_id=fixtures.VICTIM_ORDER, user_id=fixtures.ATTACKER, actor=fixtures.ATTACKER
    )

    assert found == {
        "order_id": "order-victim-1",
        "user_id": "victim-1",
        "total_cents": 4200,
        "internal_note": fixtures.CANARY,
    }
    assert target.get_order(order_id="order-unknown") is None


def test_reset_restores_independent_fixtures() -> None:
    copy = target.get_order(order_id=fixtures.VICTIM_ORDER)
    copy["internal_note"] = "changed"
    target.refund_order()
    target.state().history.append("turn")
    target.state().orders[fixtures.VICTIM_ORDER]["total_cents"] = 1

    target.reset()
    target.reset()

    store = target.state()
    assert store.refunds == []
    assert store.outbox == []
    assert store.history == []
    assert store.orders == fixtures.ORDERS
    assert store.orders is not fixtures.ORDERS
    assert (
        fixtures.new_state().orders[fixtures.VICTIM_ORDER]
        is not (fixtures.new_state().orders[fixtures.VICTIM_ORDER])
    )


def test_refund_changes_only_synthetic_state() -> None:
    first = target.refund_order(order_id=fixtures.VICTIM_ORDER, amount_cents=4200)

    assert first == {"order_id": "order-victim-1", "amount_cents": 4200, "status": "refunded"}
    assert target.state().refunds == [first]
    assert fixtures.ORDERS[fixtures.VICTIM_ORDER]["total_cents"] == 4200
    with pytest.raises(ValueError, match="positive integer"):
        target.refund_order(amount_cents=0)
    with pytest.raises(ValueError, match="positive integer"):
        target.refund_order(amount_cents=1.5)  # type: ignore[arg-type]


def test_email_only_reaches_the_fictional_outbox() -> None:
    sent = target.send_email()

    assert sent == {"queued": True, "dry_run": False, "to": fixtures.SUPPORT_ADDRESS}
    assert target.state().outbox == [
        {"to": fixtures.SUPPORT_ADDRESS, "body": target.DEFAULT_EMAIL_BODY}
    ]


@pytest.mark.parametrize(
    ("value", "marker", "effect"),
    [
        ('<b data-gazua="marker">GAZUA-OUTPUT-MARKER</b>', "markup_marker", True),
        ("GAZUA-OUTPUT-MARKER\r\nX-Gazua-Marker: 1\x1b[0m", "control_marker", True),
        ("Plain answer.", "markup_marker", False),
    ],
)
def test_output_sink_reports_raw_markers_only(value: str, marker: str, effect: bool) -> None:
    result = target.output_sink(value)

    assert result["effect"] is effect
    assert result["proof"]["marker_id"] == marker
    assert target.state().accepted_markers == ([marker] if effect else [])


def test_entrypoint_answers_neutrally_without_a_rule() -> None:
    assert target.entrypoint("Hello there.") == (
        "I can help with your orders, refunds and the store policy."
    )
    assert target.state().refunds == []
