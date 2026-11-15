"""The versionable baseline: accepted finding ids, their states and the scenarios they cover.

The file holds opaque identifiers only. A scenario is the SHA-256 of its original attack key
with the language it ran in; no attack text, payload, conversation, fixture, canary, path,
command or free text is ever kept. ``new`` is a state of a comparison, never of an entry.
"""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Any, Final, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, model_validator

from gazua.catalog.models import Language, Mode
from gazua.config.models import SCHEMA_DIALECT
from gazua.runtime.run_models import GazuaId, UtcTimestamp

BASELINE_SCHEMA_FILE: Final = "baseline-v1.schema.json"
BASELINE_SCHEMA_VERSION: Final = 1
BASELINE_FILE: Final = "gazua-baseline.json"
VERIFY_REPETITIONS: Final = 20
MAX_ENTRIES: Final = 10_000
MAX_SCENARIO_REFERENCES: Final = 100_000
_SCHEMA_BASE: Final = "https://raw.githubusercontent.com/JoaoVictorVM/gazua/main/src/gazua/schemas/"
LANGUAGE_SUFFIX: Final = ":lang:"

FindingId = Annotated[str, Field(pattern=r"^finding-[0-9a-f]{64}$")]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
PackageVersion = Annotated[
    str,
    Field(
        max_length=128,
        pattern=r"^[0-9]+(\.[0-9]+)*((a|b|rc)[0-9]+)?(\.post[0-9]+)?(\.dev[0-9]+)?"
        r"(\+[A-Za-z0-9]+(\.[A-Za-z0-9]+)*)?$",
    ),
]
EntryStatus: TypeAlias = Literal["open", "closed"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


def scenario_digest(attack_key: str) -> str:
    """The SHA-256 of the original attack key's UTF-8 bytes; the key itself is never kept."""
    return hashlib.sha256(attack_key.encode("utf-8")).hexdigest()


def operational_key(attack_key: str, language: Language) -> str:
    """The key a verification runs under: the original key and the language it is tested in."""
    return f"{attack_key}{LANGUAGE_SUFFIX}{language}"


def original_key(attack_key: str) -> tuple[str, Language] | None:
    """The original key and language of an operational key; None for a regular key."""
    head, separator, tail = attack_key.rpartition(LANGUAGE_SUFFIX)
    if not separator or tail not in ("en", "pt") or not head:
        return None
    language: Language = "pt" if tail == "pt" else "en"
    return head, language


class ScenarioReference(_Strict):
    """One covered scenario: the digest of its original attack key and its language."""

    scenario_digest: Digest
    language: Language

    @property
    def pair(self) -> tuple[str, str]:
        return (self.scenario_digest, self.language)


def ordered_references(items: list[ScenarioReference]) -> list[ScenarioReference]:
    """Unique references, ordered by digest and language."""
    unique = {item.pair: item for item in items}
    return [unique[key] for key in sorted(unique)]


def _ordered_unique(items: list[ScenarioReference]) -> bool:
    pairs = [item.pair for item in items]
    return pairs == sorted(set(pairs))


class VerificationReceipt(_Strict):
    """The minimal record of a verification that met the closure rule.

    Its existence means every listed scenario had 20 conclusive repetitions without success.
    It is a structural check against accidental closure, not a signature against tampering.
    """

    run_id: GazuaId
    verified_at: UtcTimestamp
    repetitions: Literal[20]
    scenarios: Annotated[list[ScenarioReference], Field(min_length=1)]

    @model_validator(mode="after")
    def _ordered(self) -> VerificationReceipt:
        if not _ordered_unique(self.scenarios):
            raise ValueError("Receipt scenarios are unique and ordered.")
        return self


class BaselineEntry(_Strict):
    """One accepted finding id with its persisted state and its accumulated coverage."""

    id: FindingId
    mode: Mode
    status: EntryStatus
    scenarios: Annotated[list[ScenarioReference], Field(min_length=1)]
    verification: VerificationReceipt | None

    @model_validator(mode="after")
    def _consistent(self) -> BaselineEntry:
        if not _ordered_unique(self.scenarios):
            raise ValueError("Entry scenarios are unique and ordered.")
        if self.status == "closed":
            if self.verification is None:
                raise ValueError("A closed entry needs its verification receipt.")
            receipt = [item.pair for item in self.verification.scenarios]
            if receipt != [item.pair for item in self.scenarios]:
                raise ValueError("The receipt covers exactly the entry's scenarios.")
        elif self.verification is not None:
            raise ValueError("An open entry has no verification receipt.")
        return self


class BaselineDocument(_Strict):
    """The versionable baseline file. Its compatibility is its schema version, not Gazua's."""

    model_config = ConfigDict(title="Gazua baseline")

    schema_version: Literal[1]
    gazua_version: PackageVersion | None
    revision: Annotated[int, Field(ge=1)]
    entries: Annotated[list[BaselineEntry], Field(max_length=MAX_ENTRIES)]

    @model_validator(mode="after")
    def _consistent(self) -> BaselineDocument:
        ids = [item.id for item in self.entries]
        if ids != sorted(set(ids)):
            raise ValueError("Entry ids are unique and ordered.")
        if sum(len(item.scenarios) for item in self.entries) > MAX_SCENARIO_REFERENCES:
            raise ValueError("Too many scenario references.")
        return self

    def entry(self, finding_id: str) -> BaselineEntry | None:
        return next((item for item in self.entries if item.id == finding_id), None)


def baseline_json(document: BaselineDocument) -> str:
    """Deterministic UTF-8 JSON with a final newline: the same content gives the same bytes."""
    return json.dumps(document.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n"


def build_baseline_json_schema() -> dict[str, Any]:
    schema = BaselineDocument.model_json_schema(mode="validation")
    return {"$schema": SCHEMA_DIALECT, "$id": _SCHEMA_BASE + BASELINE_SCHEMA_FILE, **schema}


def render_baseline_json_schema() -> str:
    return json.dumps(build_baseline_json_schema(), indent=2) + "\n"


def packaged_baseline_json_schema() -> str:
    """The baseline schema distributed with this package, read without network access."""
    from importlib.resources import files

    return files("gazua").joinpath(f"schemas/{BASELINE_SCHEMA_FILE}").read_text(encoding="utf-8")
