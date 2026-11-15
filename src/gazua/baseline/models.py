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


ComparedStatus: TypeAlias = Literal["new", "open", "closed"]
VerificationOutcome: TypeAlias = Literal["verified", "still_open", "incomplete", "interrupted"]
ReasonCode = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$")]
Count = Annotated[int, Field(ge=0)]
Probability = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
AttackKey = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")]


class ComparisonEntry(_Strict):
    """One finding id as a run compares it with the baseline.

    Observed entries are the run's findings; ``native_gated`` is the finding's own gate and
    ``effective_gated`` whether it still fails the build. Unobserved entries are history the
    run did not confirm; they never gate.
    """

    finding_id: FindingId
    baseline_status: EntryStatus | None
    status: ComparedStatus
    observed: bool
    regression: bool
    native_gated: bool
    effective_gated: bool

    @model_validator(mode="after")
    def _consistent(self) -> ComparisonEntry:
        if not self.observed:
            if self.baseline_status is None or self.status != self.baseline_status:
                raise ValueError("An unobserved entry keeps its persisted state.")
            if self.regression or self.native_gated or self.effective_gated:
                raise ValueError("An unobserved entry never gates.")
            return self
        expected: ComparedStatus = "open" if self.baseline_status == "open" else "new"
        if self.status != expected:
            raise ValueError("A finding is new unless its entry is open.")
        if self.regression != (self.baseline_status == "closed"):
            raise ValueError("A regression is a finding whose entry was closed.")
        if self.effective_gated != (self.status == "new" and self.native_gated):
            raise ValueError("Only a new finding keeps its native gate.")
        return self


class BaselineComparison(_Strict):
    """A run's findings against the baseline it read, with no attack text.

    This is the projection CI consumers read. It never changes ``verdicts.has_gated_findings``.
    """

    schema_version: Literal[1]
    baseline_revision: Annotated[int, Field(ge=1)]
    baseline_digest: Digest
    observed_known: Count
    observed_new: Count
    has_new_gated_findings: bool
    entries: list[ComparisonEntry]

    @model_validator(mode="after")
    def _consistent(self) -> BaselineComparison:
        ids = [item.finding_id for item in self.entries]
        if len(set(ids)) != len(ids):
            raise ValueError("Each finding id appears once in a comparison.")
        observed = [item for item in self.entries if item.observed]
        if self.observed_known != sum(item.status == "open" for item in observed):
            raise ValueError("Known findings are the observed open entries.")
        if self.observed_new != sum(item.status == "new" for item in observed):
            raise ValueError("New findings are the observed new entries.")
        if self.has_new_gated_findings != any(item.effective_gated for item in observed):
            raise ValueError("The effective gate is the OR of the new findings' gates.")
        return self

    @property
    def observed(self) -> list[ComparisonEntry]:
        return [item for item in self.entries if item.observed]

    @property
    def unobserved(self) -> list[ComparisonEntry]:
        return [item for item in self.entries if not item.observed]


class VerificationSample(_Strict):
    """One scenario and language of a verification, copied from its native attack result."""

    attack_key: AttackKey
    scenario_digest: Digest
    language: Language
    planned: Annotated[int, Field(ge=VERIFY_REPETITIONS, le=VERIFY_REPETITIONS)]
    evaluated: Count
    successes: Count
    unknown: Count
    not_applicable_count: Count
    coverage: Literal["complete", "partial", "none"]
    low_fidelity: bool
    rate: Probability | None
    upper_bound: Probability | None
    confidence: Annotated[float, Field(ge=0.95, le=0.95)]

    @property
    def reference(self) -> ScenarioReference:
        return ScenarioReference(scenario_digest=self.scenario_digest, language=self.language)

    @property
    def clean(self) -> bool:
        """Twenty conclusive repetitions without success: what closure needs per scenario."""
        return (
            self.evaluated == VERIFY_REPETITIONS
            and self.successes == 0
            and self.unknown == 0
            and self.not_applicable_count == 0
            and self.coverage == "complete"
            and not self.low_fidelity
        )


class VerificationResult(_Strict):
    """The decision a verification proposes, saved in its report before the baseline changes.

    It states what the evidence allows, not that the baseline was written.
    """

    finding_id: FindingId
    previous_status: EntryStatus
    proposed_status: EntryStatus | None
    outcome: VerificationOutcome
    closure_eligible: bool
    interrupted: bool
    reasons: list[ReasonCode]
    samples: list[VerificationSample]

    @model_validator(mode="after")
    def _consistent(self) -> VerificationResult:
        pairs = [item.reference.pair for item in self.samples]
        if len(set(pairs)) != len(pairs):
            raise ValueError("Each scenario and language is sampled once.")
        successes = any(item.successes for item in self.samples)
        if self.outcome == "verified":
            if self.proposed_status != "closed" or not self.closure_eligible:
                raise ValueError("A verified finding proposes closure.")
            if not self.samples or not all(item.clean for item in self.samples):
                raise ValueError("Closure needs 0/20 in every scenario.")
        elif self.closure_eligible:
            raise ValueError("Only a verified finding is eligible for closure.")
        if self.outcome == "still_open" and (self.proposed_status != "open" or not successes):
            raise ValueError("A finding stays open only with a success.")
        if self.outcome == "incomplete" and self.proposed_status == "closed":
            raise ValueError("An incomplete verification never closes.")
        if self.outcome == "incomplete" and self.proposed_status == "open" and not successes:
            raise ValueError("An incomplete verification reopens only with a success.")
        if self.outcome == "interrupted" and (
            self.proposed_status is not None or not self.interrupted
        ):
            raise ValueError("An interrupted verification proposes nothing.")
        if self.interrupted and self.outcome != "interrupted":
            raise ValueError("An interruption wins over every other outcome.")
        return self

    def downgraded(self, reason: str) -> VerificationResult:
        """The same samples as an incomplete verification, after an operational error."""
        if self.outcome in ("incomplete", "interrupted"):
            if reason in self.reasons:
                return self
            return self.model_copy(update={"reasons": [*self.reasons, reason]})
        successes = any(item.successes for item in self.samples)
        return VerificationResult(
            finding_id=self.finding_id,
            previous_status=self.previous_status,
            proposed_status="open" if successes else None,
            outcome="incomplete",
            closure_eligible=False,
            interrupted=False,
            reasons=[*self.reasons, reason],
            samples=list(self.samples),
        )

    @property
    def exit_code(self) -> Literal[0, 1, 2]:
        if self.outcome == "verified":
            return 0
        return 1 if self.outcome == "still_open" else 2


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
