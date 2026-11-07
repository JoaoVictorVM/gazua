"""Selects molds by mode and checks their declared requirements against the configuration.

The result describes declarations only. It is not a verdict: a mold that is eligible by
configuration still depends on run-time checks, and nothing here counts as resisted.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Final, Literal, TypeAlias

from gazua.catalog.loader import CatalogEntry
from gazua.catalog.models import (
    DAMAGES,
    MODES,
    RUNTIME_REQUIREMENTS,
    Entry,
    Mode,
    Mold,
    Requirement,
    ordered_requirements,
)
from gazua.config.models import GazuaConfig, Tool, ToolClass

ListingStatus: TypeAlias = Literal[
    "eligible_by_config", "missing_declarations", "runtime_unverified"
]
ADAPTER_PENDING_ENTRIES: Final[frozenset[Entry]] = frozenset(
    {"web_page", "attachment", "mcp_tool_description"}
)

_TOOL_CHECKS: dict[Requirement, Callable[[Tool], bool]] = {
    "tool.forbidden": lambda tool: tool.classification is ToolClass.FORBIDDEN,
    "tool.sensitive": lambda tool: tool.classification is ToolClass.SENSITIVE,
    "tool.safe": lambda tool: tool.safe,
    "tool.classified": lambda tool: tool.classification is not ToolClass.UNCLASSIFIED,
    "tool.owner_arg": lambda tool: tool.owner_arg is not None,
}


@dataclass(frozen=True)
class RequirementReport:
    """Requirements split by what the configuration can tell.

    ``conditional`` holds an absent output sink: the attempt still runs and the consumer
    reports a conditional risk instead of a finding.
    """

    satisfied: tuple[Requirement, ...]
    missing: tuple[Requirement, ...]
    unverified: tuple[Requirement, ...]
    conditional: tuple[Requirement, ...] = ()
    config_loaded: bool = True

    @property
    def status(self) -> ListingStatus:
        if self.missing:
            return "missing_declarations"
        return "eligible_by_config" if self.config_loaded else "runtime_unverified"


def _sort_key(entry: CatalogEntry) -> tuple[int, int, str]:
    mold = entry.mold
    return DAMAGES.index(mold.damage), MODES.index(mold.modes[0]), mold.id


def select_molds(
    entries: Iterable[CatalogEntry], mode: Mode | None = None
) -> tuple[CatalogEntry, ...]:
    """Stable order by damage, mode and id. A mode filter is exact, with no fallback."""
    chosen: dict[str, CatalogEntry] = {}
    for entry in entries:
        if mode is None or mode in entry.mold.supported_modes:
            chosen.setdefault(entry.id, entry)
    return tuple(sorted(chosen.values(), key=_sort_key))


def _tool_requirements(
    required: tuple[Requirement, ...], tools: list[Tool]
) -> tuple[set[Requirement], set[Requirement], list[Tool]]:
    satisfied: set[Requirement] = set()
    missing: set[Requirement] = set()
    candidates = tools
    for requirement in required:
        check = _TOOL_CHECKS.get(requirement)
        if check is None:
            continue
        matching = [tool for tool in candidates if check(tool)]
        if matching:
            satisfied.add(requirement)
            candidates = matching
        else:
            missing.add(requirement)
    return satisfied, missing, candidates


def inspect_requirements(
    mold: Mold, config: GazuaConfig | None = None, tool_name: str | None = None
) -> RequirementReport:
    """Which effective requirements the configuration satisfies, misses or cannot tell.

    With ``tool_name`` the tool requirements apply to that tool only. Without it, one declared
    tool has to satisfy all of them together.
    """
    required = mold.effective_requirements
    runtime: list[Requirement] = [item for item in required if item in RUNTIME_REQUIREMENTS]
    if config is None:
        return RequirementReport(
            satisfied=(),
            missing=(),
            unverified=ordered_requirements(required),
            config_loaded=False,
        )
    if tool_name is not None:
        bound = config.tools.get(tool_name)
        tools = [bound] if bound is not None else []
    else:
        tools = list(config.tools.values())
    satisfied, missing, candidates = _tool_requirements(required, tools)
    attacker, victim = config.fixtures.attacker, config.fixtures.victim
    declared: dict[Requirement, bool] = {
        "identity": config.target.as_user is not None
        or any(tool.actor_arg is not None for tool in candidates),
        "fixtures.attacker": attacker is not None,
        "fixtures.victim": victim is not None,
        "fixtures.victim.records": victim is not None and bool(victim.records),
        "canaries": bool(config.canaries),
        "output_sink": config.output_sink is not None,
        "target.reset": config.target.reset is not None,
    }
    conditional: set[Requirement] = set()
    for requirement in required:
        if requirement not in declared:
            continue
        if declared[requirement]:
            satisfied.add(requirement)
        elif requirement == "output_sink" and mold.damage == "unhandled_output":
            conditional.add(requirement)
        else:
            missing.add(requirement)
    return RequirementReport(
        satisfied=ordered_requirements(satisfied),
        missing=ordered_requirements(missing),
        unverified=ordered_requirements(runtime),
        conditional=ordered_requirements(conditional),
    )


def adapter_pending(mold: Mold) -> bool:
    """True when the mold's entry needs a transport adapter that has not been verified."""
    return "agent" in mold.supported_modes and mold.entry in ADAPTER_PENDING_ENTRIES
