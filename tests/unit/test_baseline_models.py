import pytest
from baseline_factory import DIGEST_A, DIGEST_B, FINDING_A, FINDING_B, document_data, entry
from baseline_factory import reference as ref
from pydantic import ValidationError

from gazua.baseline.models import (
    BaselineDocument,
    BaselineEntry,
    operational_key,
    original_key,
    scenario_digest,
)


def test_rejects_duplicate_ids_and_scenarios() -> None:
    with pytest.raises(ValidationError):
        BaselineDocument.model_validate(
            {**document_data(), "entries": [entry(FINDING_A), entry(FINDING_A)]}
        )
    with pytest.raises(ValidationError):
        BaselineEntry.model_validate(entry(scenarios=[ref(), ref()]))
    with pytest.raises(ValidationError):
        BaselineEntry.model_validate(entry(scenarios=[ref(DIGEST_B), ref(DIGEST_A)]))
    with pytest.raises(ValidationError):
        BaselineEntry.model_validate(entry(scenarios=[]))

    accepted = BaselineDocument.model_validate(document_data(entry(FINDING_A), entry(FINDING_B)))

    assert [item.id for item in accepted.entries] == [FINDING_A, FINDING_B]


def test_closed_requires_matching_receipt() -> None:
    closed = entry(status="closed", scenarios=[ref(), ref(DIGEST_B)])
    assert BaselineEntry.model_validate(closed).status == "closed"

    missing = {**closed, "verification": None}
    with pytest.raises(ValidationError):
        BaselineEntry.model_validate(missing)

    narrower = {**closed, "verification": {**closed["verification"], "scenarios": [ref()]}}
    with pytest.raises(ValidationError):
        BaselineEntry.model_validate(narrower)

    open_with_receipt = {**closed, "status": "open"}
    with pytest.raises(ValidationError):
        BaselineEntry.model_validate(open_with_receipt)

    fewer = {**closed, "verification": {**closed["verification"], "repetitions": 5}}
    with pytest.raises(ValidationError):
        BaselineEntry.model_validate(fewer)


@pytest.mark.parametrize(
    "extra",
    [
        {"attack": "Direct access to the victim record"},
        {"payload": {"order_id": "order-victim-1"}},
        {"conversation": ["hi"]},
        {"reproduction": ["gazua", "run"]},
        {"note": "free text"},
    ],
)
def test_rejects_extra_attack_fields(extra: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        BaselineEntry.model_validate({**entry(), **extra})
    with pytest.raises(ValidationError):
        BaselineDocument.model_validate({**document_data(), **extra})


def test_strict_types_refuse_booleans_and_new_status() -> None:
    with pytest.raises(ValidationError):
        BaselineDocument.model_validate({**document_data(), "revision": True})
    with pytest.raises(ValidationError):
        BaselineEntry.model_validate({**entry(), "status": "new"})
    with pytest.raises(ValidationError):
        BaselineEntry.model_validate({**entry(), "id": "idor-01"})
    with pytest.raises(ValidationError):
        BaselineDocument.model_validate({**document_data(), "gazua_version": "latest build"})


def test_operational_key_round_trips_and_keeps_digest_of_original() -> None:
    key = "tools:idor-01:" + "c" * 64
    operational = operational_key(key, "pt")

    assert original_key(operational) == (key, "pt")
    assert original_key(key) is None
    assert scenario_digest(key) != scenario_digest(operational)
    assert len(scenario_digest(key)) == 64
