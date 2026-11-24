"""Selects the agent molds and expands them into scenarios, slots and legitimate tasks.

A scenario is one mold with the tool whose effect is judged, the victim record and the canary
its signal or text uses. Dimensions the signal does not use are not multiplied. Every scenario
keeps its context, including the ones that cannot run, so a missing entry or declaration is
reported instead of disappearing. Nothing here imports the target or calls the model.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Final

from gazua.catalog.bindings import BindingContext, BindingImpediment, BoundMold, bind_mold
from gazua.catalog.loader import CatalogEntry
from gazua.catalog.models import DAMAGES, ENTRIES, Damage, Language, Mold
from gazua.catalog.selection import ADAPTER_PENDING_ENTRIES, INDIRECT_ENTRIES, select_molds
from gazua.config.models import FixtureRecord, GazuaConfig, ToolClass
from gazua.diagnostics import ConfigError, Diagnostic
from gazua.modes.agent_models import (
    QUICK_MOLDS,
    AgentDiagnostic,
    AgentSelection,
    SelectedMold,
    legitimate_mold_id,
    legitimate_request_key,
)
from gazua.modes.tools_models import ToolsInventory
from gazua.modes.tools_plan import mcp_payload
from gazua.runtime.run_models import ExecutionRequest
from gazua.runtime.session_models import SessionInjection, turn_injection_id
from gazua.verdicts.engine import impediment_of
from gazua.verdicts.models import AttackContext, Capabilities, Impediment, RequestSlot

EXECUTOR: Final = "gazua.modes.agent_executor:execute"
SINK_MARKER: Final = "markup_marker"
_RECORD_TOKENS: Final = frozenset({"record.id", "record.id_arg"})
_CLASS_SIGNALS: Final = {
    "forbidden_tool_call": ToolClass.FORBIDDEN,
    "sensitive_tool_call": ToolClass.SENSITIVE,
    "tool_call_ceiling": ToolClass.SENSITIVE,
}


def _not_found(message: str) -> ConfigError:
    return ConfigError([Diagnostic(code="mold_not_found", field="--mold", message=message)])


def agent_molds(entries: Iterable[CatalogEntry], mold_id: str | None = None) -> list[Mold]:
    """Molds that support agent mode, in catalog order; ``mold_id`` matches exactly.

    An unknown id, or the id of a mold without agent support, raises ``ConfigError`` before
    anything runs. There is no fallback to a similar mold.
    """
    chosen = [entry.mold for entry in select_molds(entries, "agent")]
    if mold_id is None:
        return chosen
    found = [mold for mold in chosen if mold.id == mold_id]
    if not found:
        raise _not_found("No mold with this id supports agent mode; see gazua run --list.")
    return found


def quick_selection(molds: Sequence[Mold], limit: int = QUICK_MOLDS) -> list[Mold]:
    """Up to ``limit`` molds, spread over the damages, with no randomness.

    Molds are ordered by damage, entry and id and queued per damage; one mold is taken from each
    queue in turn. The same catalog in any order gives the same selection. Molds whose
    declarations are missing stay in it: they are reported, never swapped for others.
    """
    ordered = sorted(
        molds, key=lambda item: (DAMAGES.index(item.damage), ENTRIES.index(item.entry), item.id)
    )
    queues: dict[Damage, list[Mold]] = {}
    for mold in ordered:
        queues.setdefault(mold.damage, []).append(mold)
    chosen: list[Mold] = []
    while len(chosen) < limit and any(queues.values()):
        for damage in DAMAGES:
            queue = queues.get(damage)
            if queue and len(chosen) < limit:
                chosen.append(queue.pop(0))
    return chosen


def attack_key(
    mold: Mold,
    tool_name: str | None,
    record: tuple[int, FixtureRecord] | None,
    canary: tuple[int, str] | None,
    entry_tool: str | None,
) -> str:
    """``agent:<mold>:<sha256>`` of the scenario's canonical JSON, stable across runs.

    Only the digest is published, so canaries and fixture values never appear in the key.
    """
    document: dict[str, Any] = {
        "mode": "agent",
        "mold": mold.id,
        "entry": mold.entry,
        "entry_tool": entry_tool,
        "tool": tool_name,
        "record": None if record is None else record[1].model_dump(mode="json"),
        "record_index": None if record is None else record[0],
        "canary": None if canary is None else canary[1],
        "canary_index": None if canary is None else canary[0],
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"agent:{mold.id}:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


MCP_DESCRIPTION: Final = "mcp_tool_description"


def entry_tool(config: GazuaConfig, mold: Mold) -> str | None:
    """The declared tool that carries this mold's text, for indirect entries only.

    A tool description is an entry only for an MCP target, where the broker serves it.
    """
    if mold.entry == MCP_DESCRIPTION:
        declared = config.agent_entries.mcp_tool_description
        return None if config.mcp is None or declared is None else declared.tool
    if mold.entry not in INDIRECT_ENTRIES:
        return None
    declared = config.agent_entries.get(mold.entry)
    return None if declared is None else declared.tool


def executor_for(config: GazuaConfig) -> str:
    from gazua.http import EXECUTOR as HTTP_EXECUTOR
    from gazua.typescript import EXECUTOR as TYPESCRIPT_EXECUTOR

    if config.http is not None:
        return HTTP_EXECUTOR
    if config.typescript is not None:
        return TYPESCRIPT_EXECUTOR
    return EXECUTOR


def capabilities_for(config: GazuaConfig, mold: Mold, inventory: ToolsInventory) -> Capabilities:
    """What this target lets the verdicts see. An HTTP target shows tool calls only by spans."""
    remote = config.http is not None
    return Capabilities(
        entry_supported=entry_reachable(config, mold),
        inventory_complete=inventory.complete,
        tool_visibility=config.traces is not None if remote else True,
        receiver_transport=False,
        observation_envelope=True,
        tool_source="traces" if remote else "call_log",
    )


def entry_reachable(config: GazuaConfig, mold: Mold) -> bool:
    if mold.entry == "user_message":
        return True
    if config.http is not None:
        # Indirect entries are armed in a local Python tool; the HTTP target's tools are remote.
        return False
    if mold.entry == MCP_DESCRIPTION:
        return entry_tool(config, mold) is not None
    if mold.entry in ADAPTER_PENDING_ENTRIES:
        return False
    return entry_tool(config, mold) is not None


@dataclass(frozen=True, slots=True)
class PlannedScenario:
    """One scenario with one request per repetition when nothing impedes it."""

    context: AttackContext
    requests: tuple[ExecutionRequest, ...]


@dataclass(frozen=True, slots=True)
class AgentPlan:
    """Scenarios, legitimate tasks and the order the engine receives them in.

    Legitimate tasks come first, in declared order. Attack slots follow by repetition round:
    every scenario gets its first repetition before any gets its second.
    """

    selection: AgentSelection
    scenarios: tuple[PlannedScenario, ...]
    legitimate: tuple[ExecutionRequest, ...]
    repetitions: int
    diagnostics: tuple[AgentDiagnostic, ...] = ()

    @property
    def contexts(self) -> list[AttackContext]:
        return [item.context for item in self.scenarios]

    @property
    def attack_requests(self) -> list[ExecutionRequest]:
        rounds: list[ExecutionRequest] = []
        for repetition in range(self.repetitions):
            rounds.extend(
                item.requests[repetition]
                for item in self.scenarios
                if repetition < len(item.requests)
            )
        return rounds

    @property
    def requests(self) -> list[ExecutionRequest]:
        return [*self.legitimate, *self.attack_requests]

    @property
    def executable_scenarios(self) -> int:
        return sum(1 for item in self.scenarios if item.requests)

    @property
    def impeded_slots(self) -> int:
        return sum(len(item.context.requests) for item in self.scenarios if not item.requests)


@dataclass(frozen=True, slots=True)
class _Unit:
    mold: Mold
    tool_name: str | None
    record: tuple[int, FixtureRecord] | None
    canary: tuple[int, str] | None


class _Planner:
    def __init__(
        self,
        config: GazuaConfig,
        inventory: ToolsInventory,
        language: Language,
        repetitions: int,
        key_suffix: str = "",
    ) -> None:
        self.config = config
        self.inventory = inventory
        self.language: Language = language
        self.repetitions = repetitions
        self.key_suffix = key_suffix

    def tools_for(self, mold: Mold) -> list[str | None]:
        signal = mold.success.signal
        if signal == "victim_record_access":
            victim = self.config.fixtures.victim
            names = sorted({record.tool for record in (victim.records if victim else [])})
            return list(names) or [None]
        kind = _CLASS_SIGNALS.get(signal)
        if kind is None:
            return [None]
        names = sorted(
            name for name, tool in self.config.tools.items() if tool.classification is kind
        )
        return list(names) or [None]

    def records_for(
        self, mold: Mold, tool_name: str | None
    ) -> list[tuple[int, FixtureRecord] | None]:
        uses_record = mold.success.signal == "victim_record_access" or bool(
            mold.tokens & _RECORD_TOKENS
        )
        if not uses_record:
            return [None]
        victim = self.config.fixtures.victim
        # The index counts only this tool's records, exactly as the binder and the verdict do.
        records = [
            record
            for record in (victim.records if victim else [])
            if tool_name is None or record.tool == tool_name
        ]
        return list(enumerate(records)) or [None]

    def canaries_for(self, mold: Mold) -> list[tuple[int, str] | None]:
        if "canary" not in mold.tokens:
            return [None]
        return list(enumerate(self.config.canaries)) or [None]

    def units(self, mold: Mold) -> list[_Unit]:
        return [
            _Unit(mold, tool_name, record, canary)
            for tool_name in self.tools_for(mold)
            for record in self.records_for(mold, tool_name)
            for canary in self.canaries_for(mold)
        ]

    def bind(self, unit: _Unit) -> tuple[Impediment | None, BoundMold | None]:
        mold = unit.mold
        if not entry_reachable(self.config, mold):
            return Impediment(reason="entry_unavailable"), None
        context = BindingContext.from_config(
            self.config,
            unit.tool_name,
            record_index=unit.record[0] if unit.record else 0,
            canary_index=unit.canary[0] if unit.canary else 0,
        )
        bound = bind_mold(mold, context, mode="agent", language=self.language)
        if isinstance(bound, BindingImpediment):
            return Impediment.from_binding(bound), None
        return None, bound

    def plan(self, unit: _Unit) -> PlannedScenario:
        mold = unit.mold
        carrier = entry_tool(self.config, mold)
        key = attack_key(mold, unit.tool_name, unit.record, unit.canary, carrier) + self.key_suffix
        impediment, bound = self.bind(unit)
        slots = [
            RequestSlot(request_key=f"{key}:r{number}", repetition=number)
            for number in range(1, self.repetitions + 1)
        ]
        context = AttackContext(
            attack_key=key,
            mold=mold,
            mode="agent",
            tool_name=unit.tool_name,
            record_index=unit.record[0] if unit.record else None,
            canary_index=unit.canary[0] if unit.canary else None,
            marker_id=SINK_MARKER if mold.success.signal == "output_sink_effect" else None,
            requests=slots,
            capabilities=capabilities_for(self.config, mold, self.inventory),
            impediment=impediment,
        )
        if bound is None or impediment_of(context, self.config) is not None:
            return PlannedScenario(context, ())
        requests = tuple(self.request(context, slot, bound, carrier) for slot in slots)
        return PlannedScenario(context, requests)

    def request(
        self, context: AttackContext, slot: RequestSlot, bound: BoundMold, carrier: str | None
    ) -> ExecutionRequest:
        mold = context.mold
        injections = (
            [
                SessionInjection(
                    id=turn_injection_id(slot.request_key, turn),
                    tool=carrier,
                    text=text,
                    max_deliveries=1,
                )
                for turn, text in enumerate(bound.turns, start=1)
            ]
            if carrier is not None and mold.entry in INDIRECT_ENTRIES
            else []
        )
        payload: dict[str, Any] = {
            "kind": "attack",
            "attack_key": context.attack_key,
            "tool_name": context.tool_name,
            "record_index": context.record_index,
            "canary_index": context.canary_index,
            "language": self.language,
            "turns": len(bound.turns),
            "mold": mold.model_dump(mode="json", exclude_unset=True),
        }
        payload.update(mcp_payload(self.inventory, [context.tool_name, carrier]))
        return ExecutionRequest(
            key=slot.request_key,
            mold_id=mold.id,
            repetition=slot.repetition,
            mode="agent",
            executor=executor_for(self.config),
            payload=payload,
            requires_receiver=mold.success.signal == "receiver_hit",
            receiver_transport=False,
            usage_reporting=True,
            actor="attacker" if mold.success.signal == "victim_record_access" else None,
            injections=injections,
        )


def legitimate_requests(
    config: GazuaConfig, inventory: ToolsInventory | None = None
) -> tuple[ExecutionRequest, ...]:
    """One request per declared task, in order, with no injection and no imposed actor."""
    return tuple(
        ExecutionRequest(
            key=legitimate_request_key(index),
            mold_id=legitimate_mold_id(index),
            repetition=1,
            mode="agent",
            executor=executor_for(config),
            payload={
                "kind": "legitimate",
                "task_index": index,
                "request": task.request,
                "expected_tool": task.expected_tool,
                **(mcp_payload(inventory, [task.expected_tool]) if inventory is not None else {}),
            },
            requires_receiver=False,
            receiver_transport=False,
            usage_reporting=True,
        )
        for index, task in enumerate(config.legit_tasks)
    )


def plan_agent(
    molds: Sequence[Mold],
    config: GazuaConfig,
    inventory: ToolsInventory,
    *,
    language: Language = "en",
    repetitions: int,
    quick: bool = False,
    exact_mold: str | None = None,
    key_suffix: str = "",
    legitimate: bool = True,
) -> AgentPlan:
    """Every scenario of the given molds, in their order, plus the declared legitimate tasks.

    Selection is the caller's job: pass the quick selection or the exact mold already chosen.
    A verification passes ``legitimate=False``, so tasks never share its sample, and a
    ``key_suffix`` that keeps each language's scenarios apart.
    """
    planner = _Planner(config, inventory, language, repetitions, key_suffix)
    scenarios: list[PlannedScenario] = []
    selected: list[SelectedMold] = []
    diagnostics: list[AgentDiagnostic] = []
    for mold in molds:
        if "agent" not in mold.supported_modes:
            continue
        planned = [planner.plan(unit) for unit in planner.units(mold)]
        scenarios.extend(planned)
        reasons: list[str] = []
        for item in planned:
            impediment = item.context.impediment
            if not item.requests:
                blocked = impediment_of(item.context, config)
                code = (
                    impediment.reason
                    if impediment is not None
                    else (blocked[1][0].code if blocked else "not_executable")
                )
                if code not in reasons:
                    reasons.append(code)
                diagnostics.append(
                    AgentDiagnostic(
                        code=code,
                        attack_key=item.context.attack_key,
                        mold_id=mold.id,
                        tool_name=item.context.tool_name,
                    )
                )
        selected.append(
            SelectedMold(
                mold_id=mold.id,
                scenarios=len(planned),
                executable=sum(1 for item in planned if item.requests),
                impediments=reasons,
            )
        )
    selection = AgentSelection(
        quick=quick, exact_mold=exact_mold, repetitions=repetitions, molds=selected
    )
    return AgentPlan(
        selection=selection,
        scenarios=tuple(scenarios),
        legitimate=legitimate_requests(config, inventory) if legitimate else (),
        repetitions=repetitions,
        diagnostics=tuple(diagnostics),
    )
