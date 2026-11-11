"""Expands the tools molds into attack units, one per tool, fixture record and canary.

Every compatible combination gets its own context, including the ones that cannot run, so a
tool that is not ``safe: true`` or a missing fixture is reported instead of disappearing. Only
the combinations without an impediment become engine requests. Nothing here imports the target.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Final

from gazua.catalog.bindings import BindingContext, BindingImpediment, BoundMold, bind_mold
from gazua.catalog.models import InjectText, Language, Mold, ProbeOutputSink, ToolsAction
from gazua.catalog.selection import inspect_requirements
from gazua.config.models import FixtureRecord, GazuaConfig, ToolClass
from gazua.modes.tools_models import DiscoveredTool, ToolsDiagnostic, ToolsInventory
from gazua.runtime.run_models import ExecutionRequest
from gazua.verdicts.models import (
    AttackContext,
    Capabilities,
    Impediment,
    ImpedimentReason,
    RequestSlot,
)

EXECUTOR: Final = "gazua.modes.tools_executor:execute"
RECORD_ACTIONS: Final = frozenset({"read_victim_record", "probe_canary_return"})
_CLASS_ACTIONS: Final = {
    "call_forbidden": frozenset({ToolClass.FORBIDDEN}),
    "call_sensitive": frozenset({ToolClass.SENSITIVE}),
    "repeat_sensitive_call": frozenset({ToolClass.SENSITIVE}),
    "probe_output_sink": frozenset({ToolClass.FORBIDDEN, ToolClass.SENSITIVE, ToolClass.REGULAR}),
}


def needs_attacker(action: ToolsAction) -> bool:
    """Whether the call is made as the attacker, as the binding of the action prepares it."""
    if action.kind in ("call_forbidden", "call_sensitive"):
        return action.variant == "declared_actor"
    return action.kind == "read_victim_record" or action.variant == "attacker_owner"


def check_arguments(
    tool: DiscoveredTool, bound: BoundMold, config: GazuaConfig
) -> tuple[list[str], list[str]]:
    """Required parameters the call would leave empty, and arguments the tool cannot take.

    Only the binding's arguments and the actor argument the proxy imposes count; nothing else is
    guessed. An owner or actor left out on purpose by the variant is the attack, not a gap.
    """
    action = bound.action
    if isinstance(action, InjectText):
        return [], []
    declaration = config.tools.get(tool.name)
    provided = set(bound.arguments)
    omitted: set[str] = set()
    if declaration is not None:
        if needs_attacker(action) and declaration.actor_arg is not None:
            provided.add(declaration.actor_arg)
        if action.variant == "omitted_owner" and declaration.owner_arg is not None:
            omitted.add(declaration.owner_arg)
        if action.variant == "omitted_actor" and declaration.actor_arg is not None:
            omitted.add(declaration.actor_arg)
    positional = {item.name for item in tool.parameters if item.kind == "positional_only"}
    missing = [
        name
        for name in tool.required_arguments
        if name not in omitted and (name not in provided or name in positional)
    ]
    refused = sorted(name for name in provided if not tool.accepts(name))
    return missing, refused


def attack_key(
    mold: Mold,
    tool_name: str | None,
    record: tuple[int, FixtureRecord] | None,
    canary: tuple[int, str] | None,
) -> str:
    """``tools:<mold>:<sha256>`` of the unit's canonical JSON, stable across equivalent runs.

    Only the digest is published, so canary values never appear. JSON keeps the record id's
    type, and the record's declared index separates duplicates.
    """
    action = mold.tools_action
    document: dict[str, Any] = {
        "mode": "tools",
        "mold": mold.id,
        "action": None if action is None else action.model_dump(mode="json"),
        "tool": tool_name,
        "record": None if record is None else record[1].model_dump(mode="json"),
        "record_index": None if record is None else record[0],
        "canary": None if canary is None else canary[1],
        "canary_index": None if canary is None else canary[0],
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"tools:{mold.id}:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


@dataclass(frozen=True, slots=True)
class PlannedAttack:
    """One attack unit, with its engine request when nothing impedes it."""

    context: AttackContext
    request: ExecutionRequest | None
    diagnostics: tuple[ToolsDiagnostic, ...] = ()


@dataclass(frozen=True, slots=True)
class ToolsPlan:
    attacks: tuple[PlannedAttack, ...]

    @property
    def contexts(self) -> list[AttackContext]:
        return [item.context for item in self.attacks]

    @property
    def requests(self) -> list[ExecutionRequest]:
        return [item.request for item in self.attacks if item.request is not None]

    @property
    def diagnostics(self) -> list[ToolsDiagnostic]:
        return [diagnostic for item in self.attacks for diagnostic in item.diagnostics]


def _candidates(action: ToolsAction, config: GazuaConfig) -> list[str]:
    if action.kind in RECORD_ACTIONS:
        victim = config.fixtures.victim
        return sorted({record.tool for record in (victim.records if victim else [])})
    classes = _CLASS_ACTIONS[action.kind]
    return sorted(name for name, tool in config.tools.items() if tool.classification in classes)


def _records(
    action: ToolsAction, config: GazuaConfig, tool_name: str
) -> list[tuple[int, FixtureRecord] | None]:
    if action.kind not in RECORD_ACTIONS:
        return [None]
    victim = config.fixtures.victim
    # The index counts only this tool's records, exactly as the binder and the verdict do.
    records = [record for record in (victim.records if victim else []) if record.tool == tool_name]
    return list(enumerate(records)) or [None]


def _canaries(action: ToolsAction, config: GazuaConfig) -> list[tuple[int, str] | None]:
    if action.kind != "probe_canary_return":
        return [None]
    return list(enumerate(config.canaries)) or [None]


@dataclass(frozen=True, slots=True)
class _Unit:
    mold: Mold
    action: ToolsAction
    tool_name: str | None
    record: tuple[int, FixtureRecord] | None
    canary: tuple[int, str] | None


class _Planner:
    def __init__(self, config: GazuaConfig, inventory: ToolsInventory, language: Language) -> None:
        self.config = config
        self.inventory = inventory
        self.language: Language = language
        self.capabilities = Capabilities(
            direct_tool_access=True,
            inventory_complete=inventory.complete,
            tool_visibility=True,
            observation_envelope=True,
        )

    def units(self, mold: Mold) -> list[_Unit]:
        action = mold.tools_action
        if action is None:
            return []
        units: list[_Unit] = []
        for tool_name in _candidates(action, self.config):
            for record in _records(action, self.config, tool_name):
                for canary in _canaries(action, self.config):
                    units.append(_Unit(mold, action, tool_name, record, canary))
        return units or [_Unit(mold, action, None, None, None)]

    def impediment(
        self, unit: _Unit, key: str
    ) -> tuple[Impediment | None, BoundMold | None, list[ToolsDiagnostic]]:
        if unit.tool_name is None:
            if unit.action.kind in RECORD_ACTIONS:
                missing = inspect_requirements(unit.mold, self.config).missing
                return Impediment(reason="missing_declarations", missing=list(missing)), None, []
            if not self.inventory.complete:
                return Impediment(reason="tool_not_found"), None, []
            return Impediment(reason="no_applicable_tool"), None, []
        report = inspect_requirements(unit.mold, self.config, unit.tool_name)
        if report.missing:
            return Impediment(reason="missing_declarations", missing=list(report.missing)), None, []
        tool = self.inventory.get(unit.tool_name)
        blocked = self.tool_impediment(tool)
        if blocked is not None or tool is None:
            return Impediment(reason=blocked or "tool_not_found"), None, []
        context = BindingContext.from_config(
            self.config,
            unit.tool_name,
            record_index=unit.record[0] if unit.record else 0,
            canary_index=unit.canary[0] if unit.canary else 0,
        )
        bound = bind_mold(unit.mold, context, mode="tools", language=self.language)
        if isinstance(bound, BindingImpediment):
            return Impediment.from_binding(bound), None, []
        if unit.action.kind == "probe_output_sink":
            return None, bound, []
        if not tool.signature_available:
            return Impediment(reason="tool_signature_unavailable"), None, []
        missing, refused = check_arguments(tool, bound, self.config)
        diagnostics: list[ToolsDiagnostic] = []
        if missing:
            diagnostics.append(
                ToolsDiagnostic(
                    code="missing_tool_arguments",
                    attack_key=key,
                    tool_name=tool.name,
                    arguments=missing,
                )
            )
        if refused:
            diagnostics.append(
                ToolsDiagnostic(
                    code="arguments_not_accepted",
                    attack_key=key,
                    tool_name=tool.name,
                    arguments=refused,
                )
            )
        if diagnostics:
            return Impediment(reason="missing_tool_arguments"), None, diagnostics
        return None, bound, []

    def tool_impediment(self, tool: DiscoveredTool | None) -> ImpedimentReason | None:
        if tool is None or not tool.registered:
            return "tool_not_found"
        if tool.ambiguous:
            return "tool_name_conflict"
        if not tool.classified:
            return "tool_unclassified"
        return None

    def plan(self, unit: _Unit) -> PlannedAttack:
        key = attack_key(unit.mold, unit.tool_name, unit.record, unit.canary)
        request_key = f"{key}:r1"
        impediment, bound, diagnostics = self.impediment(unit, key)
        marker = unit.action.variant if isinstance(unit.action, ProbeOutputSink) else None
        context = AttackContext(
            attack_key=key,
            mold=unit.mold,
            mode="tools",
            tool_name=unit.tool_name,
            record_index=unit.record[0] if unit.record else None,
            canary_index=unit.canary[0] if unit.canary else None,
            marker_id=marker,
            requests=[RequestSlot(request_key=request_key, repetition=1)],
            capabilities=self.capabilities,
            impediment=impediment,
        )
        if bound is None:
            return PlannedAttack(context, None, tuple(diagnostics))
        request = ExecutionRequest(
            key=request_key,
            mold_id=unit.mold.id,
            repetition=1,
            mode="tools",
            executor=EXECUTOR,
            payload={
                "attack_key": key,
                "tool_name": unit.tool_name,
                "record_index": context.record_index,
                "canary_index": context.canary_index,
                "language": self.language,
                "mold": unit.mold.model_dump(mode="json", exclude_unset=True),
            },
            requires_receiver=False,
            receiver_transport=False,
            usage_reporting=False,
            actor="attacker" if needs_attacker(unit.action) else None,
        )
        return PlannedAttack(context, request, tuple(diagnostics))


def plan_tools(
    molds: Iterable[Mold],
    config: GazuaConfig,
    inventory: ToolsInventory,
    *,
    language: Language = "en",
) -> ToolsPlan:
    """Every unit of the given molds, in their order, then by tool name, record and canary.

    Molds without tools support are left out; selection is the caller's job.
    """
    planner = _Planner(config, inventory, language)
    attacks = [
        planner.plan(unit)
        for mold in molds
        if "tools" in mold.supported_modes
        for unit in planner.units(mold)
    ]
    return ToolsPlan(tuple(attacks))
