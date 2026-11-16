import pytest

from gazua.catalog.models import DAMAGES
from gazua.reports.fixes import FIXES, guide_for
from gazua.reports.guide_models import GUIDE_CATEGORIES

FORBIDDEN_CLAIMS = ("guarantee", "garant", "always secure", "100%", "proven effective")


@pytest.mark.parametrize("language", ["en", "pt"])
def test_every_damage_has_three_categories_and_confirmation(language: str) -> None:
    guide = guide_for(language)  # type: ignore[arg-type]

    assert list(guide.entries) == list(DAMAGES)
    for damage in DAMAGES:
        entry = guide.entry(damage)
        for name, _ in GUIDE_CATEGORIES:
            assert getattr(entry, name), (damage, name)
        assert "gazua verify" in entry.confirmation
        assert entry.acceptance_criteria
        assert any("20" in item for item in entry.acceptance_criteria)


def test_guide_languages_are_complete() -> None:
    english, portuguese = guide_for("en"), guide_for("pt")

    assert set(FIXES) == {"en", "pt"}
    for damage in DAMAGES:
        en, pt = english.entry(damage), portuguese.entry(damage)
        for name in ("fixes_cause", "reduces_risk", "does_not_solve", "acceptance_criteria"):
            assert len(getattr(en, name)) == len(getattr(pt, name))
        assert en != pt
    for language in ("en", "pt"):
        text = guide_for(language).model_dump_json().lower()  # type: ignore[arg-type]
        assert not {chr(0x2013), chr(0x2014)} & set(text)
        assert not any(claim in text for claim in FORBIDDEN_CLAIMS)


def test_idor_guidance_matches_required_categories() -> None:
    entry = guide_for("en").entry("idor_via_agent")

    assert "backend" in entry.fixes_cause[0]
    assert "ownership" in entry.fixes_cause[0]
    assert any("every path" in item for item in entry.fixes_cause)
    assert "confirmation" in entry.reduces_risk[0]
    assert any("reinforced prompt" in item.lower() for item in entry.does_not_solve)
    assert any("authorized in code" in item for item in entry.acceptance_criteria)
    portuguese = guide_for("pt").entry("idor_via_agent")
    assert "propriedade" in portuguese.fixes_cause[0]
    assert any("prompt reforçado" in item.lower() for item in portuguese.does_not_solve)
