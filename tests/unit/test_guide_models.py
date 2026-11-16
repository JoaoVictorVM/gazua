import json
from typing import Any

import pytest
from pydantic import ValidationError
from report_factory import document

from gazua.reports.fixes import guide_for
from gazua.reports.guide_models import FixGuide
from gazua.reports.models import RunDocument


def _guide(change: Any) -> dict[str, Any]:
    data = guide_for("en").model_dump(mode="json")
    change(data)
    return data


def test_guide_rejects_missing_damage() -> None:
    with pytest.raises(ValidationError):
        FixGuide.model_validate(_guide(lambda data: data["entries"].pop("unlocked_memory")))
    with pytest.raises(ValidationError):
        FixGuide.model_validate(
            _guide(lambda data: data["entries"].update(other=data["entries"]["idor_via_agent"]))
        )


def test_guide_rejects_wrong_language() -> None:
    data = json.loads(document().model_dump_json())
    data["guide"] = guide_for("pt").model_dump(mode="json")

    with pytest.raises(ValidationError):
        RunDocument.model_validate_json(json.dumps(data))
    with pytest.raises(ValidationError):
        FixGuide.model_validate(_guide(lambda data: data.update(language="es")))


@pytest.mark.parametrize(
    "change",
    [
        lambda data: data["entries"]["idor_via_agent"].update(confirmation="x" * 4001),
        lambda data: data["entries"]["idor_via_agent"].update(fixes_cause=["x" * 4001]),
        lambda data: data["entries"]["idor_via_agent"].update(reduces_risk=["a"] * 9),
        lambda data: data["entries"]["idor_via_agent"].update(does_not_solve=[]),
        lambda data: data["entries"]["idor_via_agent"].update(acceptance_criteria=["  "]),
        lambda data: data["entries"]["idor_via_agent"].update(extra="x"),
        lambda data: data.update(revision=0),
    ],
)
def test_guide_rejects_oversized_text(change: Any) -> None:
    with pytest.raises(ValidationError):
        FixGuide.model_validate(_guide(change))


def test_fix_ref_resolves_in_snapshot() -> None:
    built = document()

    assert built.guide.origin == "captured"
    assert built.guide.language == built.metadata.language
    for finding in built.findings:
        assert built.guide.entry(finding.fix_ref) == guide_for("en").entry(finding.damage)
    portuguese = document(language="pt")
    assert portuguese.guide == guide_for("pt")
