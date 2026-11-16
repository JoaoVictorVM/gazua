"""The fix guide kept inside a run document: one entry per damage, in the run's language.

The guide is editorial data, never a template or a shell command. A document keeps the guide it
was captured with, so its reports show the same guidance even after the installed catalog
changes. ``origin`` says whether the guide was captured by the run or added when an older
document was read.
"""

from __future__ import annotations

from typing import Annotated, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, model_validator

from gazua.catalog.models import DAMAGES, Damage, Language

GuideOrigin: TypeAlias = Literal["captured", "legacy_fallback"]
GuideText = Annotated[str, Field(min_length=1, max_length=4000, pattern=r"\S")]
GuideItems = Annotated[list[GuideText], Field(min_length=1, max_length=8)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class GuideEntry(_Strict):
    """What fixes the cause, what only reduces the risk, what does not solve it, and how to
    confirm a fix."""

    fixes_cause: GuideItems
    reduces_risk: GuideItems
    does_not_solve: GuideItems
    confirmation: GuideText
    acceptance_criteria: GuideItems


class FixGuide(_Strict):
    """Exactly the six damages, in one language, at one editorial revision."""

    revision: Annotated[int, Field(ge=1)]
    language: Language
    origin: GuideOrigin
    entries: dict[Damage, GuideEntry]

    @model_validator(mode="after")
    def _complete(self) -> FixGuide:
        if set(self.entries) != set(DAMAGES):
            raise ValueError("The guide has exactly one entry per damage.")
        return self

    def entry(self, damage: Damage) -> GuideEntry:
        return self.entries[damage]


GUIDE_CATEGORIES: tuple[tuple[str, str], ...] = (
    ("fixes_cause", "Fixes the cause"),
    ("reduces_risk", "Reduces the risk"),
    ("does_not_solve", "Does not solve"),
)
