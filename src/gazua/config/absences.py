"""What each missing declaration means for the features that consume the configuration.

Loading never fails because of these absences. Each one is reported with the result that the
consumers must apply when a dependent attack exists.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from gazua.config.diagnostics import Diagnostic
from gazua.config.models import GazuaConfig, ToolClass


class AbsenceResult(StrEnum):
    UNCLASSIFIED = "Warning; the tool stays in dry-run"
    MISSING_OWNER = "Dependent attacks are not tested, missing owner_arg"
    MISSING_IDENTITY = "IDOR attacks are not tested, missing identity"
    MISSING_FIXTURES = "Dependent attacks are not tested"
    NOT_SAFE = "Not tested in tools mode; dry-run in agent mode"
    GENERIC_RETURN = "Generic ok return; attacks flagged low fidelity"
    NO_LEGIT_TASKS = "Legitimate use: not tested"
    NO_OUTPUT_SINK = "Conditional risk, not verified"
    NO_RESET = "Memory attacks are not tested"
    LOCALHOST_ONLY = "Localhost only"


@dataclass(frozen=True, slots=True)
class Absence:
    declaration: str
    result: AbsenceResult
    tool: str | None = None


def find_absences(config: GazuaConfig) -> tuple[Absence, ...]:
    found: list[Absence] = []
    identity_hook = config.target.as_user is not None

    for name, tool in config.tools.items():
        if tool.classification is ToolClass.UNCLASSIFIED:
            found.append(Absence("sensitive, forbidden", AbsenceResult.UNCLASSIFIED, name))
        if tool.owner_arg is None:
            found.append(Absence("owner_arg", AbsenceResult.MISSING_OWNER, name))
        if tool.actor_arg is None and not identity_hook:
            found.append(Absence("actor_arg, target.as_user", AbsenceResult.MISSING_IDENTITY, name))
        if not tool.safe:
            found.append(Absence("safe", AbsenceResult.NOT_SAFE, name))
        if not tool.has_dry_run_return:
            found.append(Absence("dry_run_return", AbsenceResult.GENERIC_RETURN, name))

    if config.fixtures.attacker is None or config.fixtures.victim is None:
        found.append(Absence("fixtures", AbsenceResult.MISSING_FIXTURES))
    if not config.canaries:
        found.append(Absence("canaries", AbsenceResult.MISSING_FIXTURES))
    if not config.legit_tasks:
        found.append(Absence("legit_tasks", AbsenceResult.NO_LEGIT_TASKS))
    if config.output_sink is None:
        found.append(Absence("output_sink", AbsenceResult.NO_OUTPUT_SINK))
    if config.target.reset is None:
        found.append(Absence("target.reset", AbsenceResult.NO_RESET))
    if "allowed_targets" not in config.model_fields_set:
        found.append(Absence("allowed_targets", AbsenceResult.LOCALHOST_ONLY))
    return tuple(found)


def tool_not_found(name: str) -> Diagnostic:
    """Result for a declared tool missing from a complete registry of the running target."""
    return Diagnostic(
        code="tool_not_found", message=f"Tool {name} is declared but was not discovered."
    )
