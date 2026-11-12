import json
from typing import Any

import pytest
from pydantic import ValidationError
from report_factory import (
    CONDITIONAL,
    FOUND,
    NOT_APPLICABLE,
    NOT_TESTED,
    RESISTED,
    document,
)

from gazua.catalog.models import DAMAGES
from gazua.reports.models import RunDocument


def test_all_results_have_one_scenario() -> None:
    built = document()

    assert [item.attack_key for item in built.scenarios] == [
        item.attack_key for item in built.verdicts.results
    ]
    assert {item.state for item in built.verdicts.results} == {
        "finding",
        "resisted",
        "not_tested",
        "not_applicable",
        "conditional_risk",
    }
    assert {FOUND, RESISTED, NOT_TESTED, NOT_APPLICABLE, CONDITIONAL} == {
        item.attack_key for item in built.scenarios
    }
    assert set(built.fixes) == set(DAMAGES)


def test_only_verified_scenarios_form_findings() -> None:
    built = document()

    assert len(built.findings) == 1
    finding = built.findings[0]
    assert finding.scenarios == [FOUND]
    assert finding.damage == "idor_via_agent"
    assert finding.fix_ref == "idor_via_agent"
    assert finding.proof_ids == [item.id for item in built.proofs]
    assert "fixture_specific" in finding.conditions
    assert CONDITIONAL not in {key for item in built.findings for key in item.scenarios}
    assert built.report_exit_code == 1


def _mutated(change: Any) -> dict[str, Any]:
    data = json.loads(document().model_dump_json())
    change(data)
    return data


@pytest.mark.parametrize(
    "change",
    [
        lambda data: data["scenarios"].append(data["scenarios"][0]),
        lambda data: data["scenarios"].pop(),
        lambda data: data["findings"].append(data["findings"][0]),
        lambda data: data["proofs"].append(data["proofs"][0]),
        lambda data: data["proofs"][0].update(proof_index=7),
        lambda data: data["findings"][0].update(scenarios=[RESISTED]),
        lambda data: data["findings"][0].update(gated=not data["findings"][0]["gated"]),
        lambda data: data["findings"][0].update(fix_ref="secret_in_context"),
        lambda data: data["findings"].clear(),
        lambda data: data["fixes"].pop("unchecked_spending"),
        lambda data: data.update(run_id="GAZUA-run-other"),
        lambda data: data.update(schema_version=2),
    ],
)
def test_duplicate_or_dangling_ids_are_rejected(change: Any) -> None:
    with pytest.raises(ValidationError):
        RunDocument.model_validate_json(json.dumps(_mutated(change)))


def test_document_round_trips_through_json() -> None:
    built = document()

    assert RunDocument.model_validate_json(built.model_dump_json()) == built
