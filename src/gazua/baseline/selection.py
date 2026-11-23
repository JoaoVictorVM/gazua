"""Resolves what ``gazua verify`` was asked to verify, before the target is imported.

A full ``finding-<hash>`` selects exactly its entry. An alias is a mold id: it selects the one
baseline entry that the current configuration, catalog and target produce for that mold. Ids
are computed with the same function the reports use, from the configuration's own values;
nothing in a report is read or executed. There is no fallback to a similar finding.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from gazua.baseline.models import BaselineDocument, BaselineEntry
from gazua.catalog.loader import CatalogEntry
from gazua.catalog.models import Mode, Mold
from gazua.catalog.selection import select_molds
from gazua.config.models import GazuaConfig
from gazua.modes.tools_models import ToolsInventory

FULL_ID: Final = re.compile(r"^finding-[0-9a-f]{64}$")
MESSAGES: Final = {
    "verification_finding_unknown": (
        "No accepted finding matches this id or mold for the current target; see the baseline "
        "and gazua baseline."
    ),
    "verification_finding_ambiguous": (
        "This mold matches several accepted findings; pass --mode or the full finding id."
    ),
    "verification_coverage_changed": (
        "Scenarios accepted in the baseline can no longer be built with the current "
        "configuration, catalog or tools; restore them before verifying. Nothing was closed."
    ),
    "verification_insufficient_budget": (
        "The limits do not allow every repetition of this verification; raise them explicitly. "
        "No attack was run."
    ),
}


class VerifyError(Exception):
    """A verification that cannot start. ``code`` and ``choices`` are safe to print."""

    def __init__(self, code: str, choices: Sequence[str] = ()) -> None:
        self.code = code
        self.choices = tuple(choices)
        super().__init__(code)

    @property
    def message(self) -> str:
        return MESSAGES.get(self.code, "This verification cannot run.")


@dataclass(frozen=True, slots=True)
class Selection:
    """The accepted entry to verify, its mode and the current mold that produces it."""

    entry: BaselineEntry
    mode: Mode
    mold: Mold


def target_ref(config: GazuaConfig) -> str:
    """The target reference the reports use in finding ids.

    An MCP target is named by its transport and executable, never by its arguments, which can
    hold private paths; the entrypoint of its test agent does not change the target.
    """
    if config.mcp is not None:
        name = Path(config.mcp.command).name or config.mcp.command
        return f"mcp:stdio:{name}"
    if config.http is not None:
        from gazua.http.models import EndpointError, parse_endpoint

        # The origin only: a path or query can carry data and never names another target.
        try:
            return f"http:{parse_endpoint(config.http.endpoint).origin}"
        except EndpointError:
            return "http:invalid"
    return config.entrypoint or ""


def _placeholder() -> ToolsInventory:
    # Ids depend on configuration values only; the real inventory decides what can run later.
    return ToolsInventory(complete=False)


def group_ids(config: GazuaConfig, mode: Mode, mold: Mold) -> set[str]:
    """Every finding id the current configuration produces for this mold and mode."""
    from gazua.reports.builder import finding_id

    if mode == "tools":
        from gazua.modes.tools_plan import plan_tools

        contexts = plan_tools([mold], config, _placeholder()).contexts
    else:
        from gazua.modes.agent_plan import plan_agent

        contexts = plan_agent([mold], config, _placeholder(), repetitions=1).contexts
    ref = target_ref(config)
    return {finding_id(ref, mode, mold.id, item.tool_name) for item in contexts}


def candidates(
    config: GazuaConfig,
    entries: Iterable[CatalogEntry],
    mode: Literal["tools", "agent"] | None,
) -> dict[str, tuple[Mode, Mold]]:
    """Finding id to the mode and mold that produce it, for every supported mode."""
    found: dict[str, tuple[Mode, Mold]] = {}
    listed = tuple(entries)
    modes: tuple[Mode, ...] = ("tools", "agent") if mode is None else (mode,)
    for chosen in modes:
        for item in select_molds(listed, chosen):
            for identifier in group_ids(config, chosen, item.mold):
                found.setdefault(identifier, (chosen, item.mold))
    return found


def resolve(
    selector: str,
    baseline: BaselineDocument,
    config: GazuaConfig,
    entries: Iterable[CatalogEntry],
    mode: Literal["tools", "agent"] | None = None,
) -> Selection:
    """The single accepted entry ``selector`` names; ``VerifyError`` otherwise."""
    known = candidates(config, entries, mode)
    if FULL_ID.fullmatch(selector):
        entry = baseline.entry(selector)
        match = known.get(selector)
        if entry is None or match is None or match[0] != entry.mode:
            raise VerifyError("verification_finding_unknown")
        return Selection(entry, match[0], match[1])
    matches = sorted(
        identifier
        for identifier, (_, mold) in known.items()
        if mold.id == selector and baseline.entry(identifier) is not None
    )
    if not matches:
        raise VerifyError("verification_finding_unknown")
    if len(matches) > 1:
        raise VerifyError("verification_finding_ambiguous", matches)
    entry = baseline.entry(matches[0])
    if entry is None:
        raise VerifyError("verification_finding_unknown")
    chosen_mode, mold = known[matches[0]]
    return Selection(entry, chosen_mode, mold)


__all__ = [
    "MESSAGES",
    "Selection",
    "VerifyError",
    "candidates",
    "group_ids",
    "resolve",
    "target_ref",
]
