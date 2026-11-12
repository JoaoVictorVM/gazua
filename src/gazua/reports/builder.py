"""Builds the run document from native results, attack contexts and treated excerpts.

Nothing here recomputes a state, rate, bound, severity or gate. Findings group the proven
scenarios of one target, mode, mold and tool under an id that does not depend on the run, the
model, the fixture or the folder. Every text that came from the configuration, the catalog or
the target passes through the treatment before it reaches the document.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol, cast

from pydantic import JsonValue

from gazua.catalog.models import (
    DAMAGES,
    CallForbidden,
    CallSensitive,
    Damage,
    Language,
    Mode,
    ProbeCanaryReturn,
    ProbeOutputSink,
    ReadVictimRecord,
    RepeatSensitiveCall,
)
from gazua.config.models import GazuaConfig, Severity
from gazua.reports.fixes import fix_text, fixes_for
from gazua.reports.models import (
    PRESENTATION_VERSION,
    SEVERITY_ORDER,
    ExitCode,
    Finding,
    ProofSnapshot,
    RedactionMode,
    ReportDiagnostic,
    Reproduction,
    RunDocument,
    RunMetadata,
    Scenario,
    SnapshotSource,
    SyntheticData,
    SyntheticIdentity,
    SyntheticRecord,
    highest_severity,
)
from gazua.runtime.run_models import RunSummary
from gazua.verdicts.models import (
    AttackContext,
    AttackResult,
    Proof,
    ProofCondition,
    VerdictSummary,
)

MAX_JSON_DEPTH = 64


class Treatment(Protocol):
    """How text and data are treated before they reach a document."""

    @property
    def mode(self) -> RedactionMode: ...

    def text(self, value: str, field: str) -> str: ...

    def data(self, value: object, field: str) -> JsonValue: ...

    def diagnostics(self) -> list[ReportDiagnostic]: ...


class NotJsonError(ValueError):
    """A value that is not plain JSON data. Its content is never part of the message."""


def plain_json(value: object, depth: int = 0) -> JsonValue:
    """The value when it is plain JSON data; raises ``NotJsonError`` for anything else.

    Only JSON types are accepted, so no property or ``repr`` of a foreign object runs.
    """
    if depth > MAX_JSON_DEPTH:
        raise NotJsonError("depth")
    kind = type(value)
    if value is None or kind in (bool, int, str):
        return cast("JsonValue", value)
    if kind is float:
        if not math.isfinite(cast("float", value)):
            raise NotJsonError("float")
        return cast("float", value)
    if kind is list:
        return [plain_json(item, depth + 1) for item in cast("list[object]", value)]
    if kind is dict:
        found: dict[str, JsonValue] = {}
        for key, item in cast("dict[object, object]", value).items():
            if type(key) is not str:
                raise NotJsonError("key")
            found[key] = plain_json(item, depth + 1)
        return found
    raise NotJsonError("type")


@dataclass(slots=True)
class PlainTreatment:
    """Keeps text as it is; for documents whose data was already treated, and for tests."""

    mode: RedactionMode = "masked"
    found: list[ReportDiagnostic] = field(default_factory=list[ReportDiagnostic])

    def text(self, value: str, field: str) -> str:
        return value

    def data(self, value: object, field: str) -> JsonValue:
        try:
            return plain_json(value)
        except NotJsonError:
            self.found.append(ReportDiagnostic(code="redaction_failed", field=field, level="error"))
            return "[redacted-field]"

    def diagnostics(self) -> list[ReportDiagnostic]:
        return list(self.found)


@dataclass(frozen=True, slots=True)
class Excerpt:
    """What the capture kept for one proof, already treated and limited."""

    content: JsonValue
    truncated: bool = False
    omission_reason: str | None = None


class ExcerptSource(Protocol):
    def excerpts(self, items: Sequence[ProofItem]) -> list[Excerpt]: ...


@dataclass(frozen=True, slots=True)
class ProofItem:
    """One native proof with where it sits in the verdicts."""

    attack_key: str
    proof_index: int
    proof: Proof
    source: SnapshotSource


def finding_id(target_ref: str, mode: Mode, mold_id: str, tool_name: str | None) -> str:
    """``finding-`` and the SHA-256 of the canonical JSON of target, mode, mold and tool.

    Only the digest is published; the canonical document is never written anywhere.
    """
    canonical = json.dumps(
        [target_ref, mode, mold_id, tool_name], separators=(",", ":"), ensure_ascii=False
    )
    return "finding-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def proof_source(proof: Proof) -> SnapshotSource:
    """Which kind of evidence holds what the proof points to."""
    signal = proof.signal
    if signal in ("forbidden_tool_call", "sensitive_tool_call", "canary_in_tool_arguments"):
        return "call"
    if signal == "victim_record_access":
        return "tool_return"
    if signal == "canary_in_response":
        return "tool_return" if proof.position == "tool_return" else "output"
    if signal == "receiver_hit":
        return "receiver"
    if signal == "output_sink_effect":
        return "sink"
    if signal == "memory_effect":
        return "memory"
    return "operational"


def _ordinal(index: int | None) -> str:
    return "#?" if index is None else f"#{index}"


def attack_description(context: AttackContext, tool: str | None, language: Language) -> str:
    """What the attack does, from a fixed template. Tools mode describes an action."""
    if context.mode == "agent":
        return "\n\n".join(context.mold.turns(language))
    action = context.mold.tools_action
    name = tool or "the tool"
    if isinstance(action, CallForbidden | CallSensitive):
        declared = "forbidden" if isinstance(action, CallForbidden) else "sensitive"
        actor = "as the attacker" if action.variant == "declared_actor" else "without an actor"
        return f"Direct call to {name}, declared {declared}, {actor}."
    if isinstance(action, ReadVictimRecord):
        variants = {
            "victim_owner": "naming the victim as owner",
            "attacker_owner": "naming the attacker as owner",
            "omitted_owner": "without an owner argument",
            "string_record_id": "with the record id as text",
        }
        return (
            f"Direct access to the declared victim record {_ordinal(context.record_index)} "
            f"through {name} as the attacker, {variants[action.variant]}."
        )
    if isinstance(action, ProbeCanaryReturn):
        return (
            f"Read of a test record through {name}, checking whether canary "
            f"{_ordinal(context.canary_index)} comes back."
        )
    if isinstance(action, ProbeOutputSink):
        marker = "markup" if action.variant == "markup_marker" else "control"
        return f"Gazua's constant {marker} marker sent to the declared output sink."
    if isinstance(action, RepeatSensitiveCall):
        return f"Repeated calls to {name}, declared sensitive, past the default ceiling."
    return "Attack without a tools action."


def _payload(context: AttackContext, language: Language) -> JsonValue:
    if context.mode == "agent":
        return list(context.mold.turns(language))
    action = context.mold.tools_action
    return None if action is None else action.model_dump(mode="json")


def reproduction_for(argv: Sequence[str] | None, treatment: Treatment) -> Reproduction:
    """The command as the document keeps it; unavailable when treatment changed an argument."""
    if not argv:
        return Reproduction(argv=[], available=False, reason="not_reproducible")
    original = list(argv)
    if any(not item.isprintable() for item in original):
        shown = ["".join(c if c.isprintable() else "?" for c in item) for item in original]
        treated = [treatment.text(item, "reproduction.argv") for item in shown]
        return Reproduction(argv=treated, available=False, reason="argument_control_characters")
    treated = [treatment.text(item, "reproduction.argv") for item in original]
    if treated != original:
        return Reproduction(argv=treated, available=False, reason="argument_redacted")
    return Reproduction(argv=treated, available=True)


def synthetic_data(config: GazuaConfig | None) -> SyntheticData:
    """Only declared fixtures and canaries, never the rest of the configuration."""
    if config is None:
        return SyntheticData()
    identities: list[SyntheticIdentity] = []
    records: list[SyntheticRecord] = []
    for role in ("attacker", "victim"):
        identity = getattr(config.fixtures, role)
        if identity is None:
            continue
        identities.append(SyntheticIdentity(role=role, id=identity.id))
        records.extend(
            SyntheticRecord(owner=role, tool=item.tool, id_arg=item.id_arg, id=item.id)
            for item in identity.records
        )
    return SyntheticData(identities=identities, records=records, canaries=list(config.canaries))


def _treated_facts(proof: Proof, treatment: Treatment, field: str) -> Proof:
    facts = treatment.data(proof.facts, field)
    if not isinstance(facts, dict):
        facts = {"redacted_field": "[redacted-field]"}
    return proof.model_copy(update={"facts": facts})


def _treated_verdicts(verdicts: VerdictSummary, treatment: Treatment) -> VerdictSummary:
    results: list[AttackResult] = []
    for result in verdicts.results:
        proofs = [
            _treated_facts(proof, treatment, f"verdicts.{result.attack_key}.proof.{index}.facts")
            for index, proof in enumerate(result.proof)
        ]
        results.append(result.model_copy(update={"proof": proofs}))
    return verdicts.model_copy(update={"results": results})


def _locator(proof: Proof) -> dict[str, JsonValue]:
    values: dict[str, JsonValue] = {
        "signal": proof.signal,
        "execution_id": proof.execution_id,
        "call_seq": proof.call_seq,
        "hit_id": proof.hit_id,
        "reference": proof.reference,
        "position": proof.position,
        "canary_index": proof.canary_index,
        "facts": dict(proof.facts),
    }
    return {key: value for key, value in values.items() if value is not None}


def _finding_order(item: Finding) -> tuple[int, int, str, str, str]:
    return (
        SEVERITY_ORDER[item.severity],
        DAMAGES.index(item.damage),
        item.tool_name or "",
        item.mold_id,
        item.id,
    )


def build_run_document(
    *,
    run_id: str,
    created_at: str,
    target_ref: str,
    mode: Mode,
    language: Language,
    engine: RunSummary,
    verdicts: VerdictSummary,
    contexts: Sequence[AttackContext],
    reproduction: Mapping[str, Sequence[str]],
    treatment: Treatment,
    exit_code: ExitCode,
    config: GazuaConfig | None = None,
    excerpts: ExcerptSource | None = None,
    gazua_version: str | None = None,
    target_version: str | None = None,
    model: str | None = None,
    diagnostics: Sequence[ReportDiagnostic] = (),
) -> RunDocument:
    """The validated document of one run. Each result appears once, in planned order."""
    by_key = {context.attack_key: context for context in contexts}
    treated = _treated_verdicts(verdicts, treatment)
    scenarios: list[Scenario] = []
    for result in treated.results:
        context = by_key[result.attack_key]
        tool = (
            None
            if context.tool_name is None
            else treatment.text(context.tool_name, f"scenarios.{result.attack_key}.tool_name")
        )
        scenarios.append(
            Scenario(
                attack_key=result.attack_key,
                mold_id=result.mold_id,
                tool_name=tool,
                record_index=context.record_index,
                canary_index=context.canary_index,
                entry=context.mold.entry,
                technique=context.mold.technique,
                attack=treatment.text(
                    attack_description(context, tool, language),
                    f"scenarios.{result.attack_key}.attack",
                ),
                payload=treatment.data(
                    _payload(context, language), f"scenarios.{result.attack_key}.payload"
                ),
                reproduction=reproduction_for(reproduction.get(result.attack_key), treatment),
            )
        )
    items = [
        ProofItem(result.attack_key, index, proof, proof_source(proof))
        for result in treated.results
        if result.state == "finding"
        for index, proof in enumerate(result.proof)
    ]
    found = (
        excerpts.excerpts(items)
        if excerpts is not None
        else [Excerpt(None, omission_reason="excerpt_not_captured") for _ in items]
    )
    snapshots = [
        ProofSnapshot(
            id=f"proof-{number:06d}",
            attack_key=item.attack_key,
            proof_index=item.proof_index,
            execution_id=item.proof.execution_id,
            source=item.source,
            locator=_locator(item.proof),
            content=excerpt.content,
            truncated=excerpt.truncated,
            omission_reason=excerpt.omission_reason,
        )
        for number, (item, excerpt) in enumerate(zip(items, found, strict=True), start=1)
    ]
    findings = _findings(target_ref, treated, scenarios, snapshots, by_key, language)
    all_diagnostics = _unique_diagnostics([*diagnostics, *treatment.diagnostics()])
    final_exit: ExitCode = (
        2 if any(item.level == "error" for item in all_diagnostics) else exit_code
    )
    return RunDocument(
        schema_version=1,
        run_id=run_id,
        metadata=RunMetadata(
            created_at=created_at,
            gazua_version=gazua_version,
            target_version=target_version,
            model=model,
            mode=mode,
            target_ref=treatment.text(target_ref, "metadata.target_ref"),
            language=language,
            presentation_version=PRESENTATION_VERSION,
        ),
        redaction=treatment.mode,
        synthetic_data=synthetic_data(config),
        engine=engine,
        verdicts=treated,
        scenarios=scenarios,
        findings=findings,
        proofs=snapshots,
        fixes=fixes_for(language),
        diagnostics=all_diagnostics,
        report_exit_code=final_exit,
    )


def _unique_diagnostics(items: Sequence[ReportDiagnostic]) -> list[ReportDiagnostic]:
    found: list[ReportDiagnostic] = []
    for item in items:
        if item not in found:
            found.append(item)
    return found


def _findings(
    target_ref: str,
    verdicts: VerdictSummary,
    scenarios: Sequence[Scenario],
    snapshots: Sequence[ProofSnapshot],
    contexts: Mapping[str, AttackContext],
    language: Language,
) -> list[Finding]:
    shown = {item.attack_key: item for item in scenarios}
    groups: dict[str, list[AttackResult]] = {}
    for result in verdicts.results:
        if result.state != "finding" or not result.proof:
            continue
        context = contexts[result.attack_key]
        key = finding_id(target_ref, result.mode, result.mold_id, context.tool_name)
        groups.setdefault(key, []).append(result)
    findings: list[Finding] = []
    for identifier, members in groups.items():
        first = members[0]
        keys = [item.attack_key for item in members]
        damage: Damage = first.damage
        severity: Severity = highest_severity(item.severity for item in members)
        conditions: list[ProofCondition] = []
        for item in members:
            for proof in item.proof:
                conditions.extend(c for c in proof.conditions if c not in conditions)
        scenario = shown[first.attack_key]
        findings.append(
            Finding(
                id=identifier,
                mode=first.mode,
                mold_id=first.mold_id,
                tool_name=scenario.tool_name,
                damage=damage,
                severity=severity,
                gated=any(item.gated for item in members),
                scenarios=keys,
                attack=scenario.attack,
                proof_ids=[item.id for item in snapshots if item.attack_key in keys],
                conditions=conditions,
                reproduction=scenario.reproduction,
                fix_ref=damage,
                fix=fix_text(damage, language),
            )
        )
    return sorted(findings, key=_finding_order)
