"""The guide added to documents written before runs captured one.

It is a frozen copy of the first editorial revision, packaged as data, so reading an old
document never depends on the installed catalog, which may change. Every guide built here is
marked ``legacy_fallback`` and the reports say it was added on reading.
"""

from __future__ import annotations

import json
from functools import cache
from importlib.resources import files
from typing import Any, Final

from gazua.catalog.models import DAMAGES, Language
from gazua.reports.guide_models import FixGuide

FALLBACK_REVISION: Final = 1
FALLBACK_FILE: Final = "reports/guides/fallback-r1.json"


@cache
def _frozen() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(
        files("gazua").joinpath(FALLBACK_FILE).read_text(encoding="utf-8")
    )
    return data


def fallback_guide(language: Language) -> FixGuide:
    data = _frozen()
    entries = data["languages"][language]
    return FixGuide.model_validate(
        {
            "revision": data["revision"],
            "language": language,
            "origin": "legacy_fallback",
            "entries": {damage: entries[damage] for damage in DAMAGES},
        }
    )
