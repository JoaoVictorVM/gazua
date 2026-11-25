"""Typed options of the pytest plugin and the minimal result of one mold as a test.

The result keeps the CI projection of the mold's findings and native counts, never attack
text, payloads or proof, so a failure message cannot carry them.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from gazua.ci.models import CiFinding

ITEM_PREFIX: Final = "gazua::"
TestState = Literal["failed", "xfailed", "passed", "skipped"]


@dataclass(frozen=True, slots=True)
class GazuaOptions:
    """What the command line asked for. ``molds`` is empty when every tools mold runs."""

    enabled: bool
    config: Path
    molds: tuple[str, ...]
    baseline: Path | None

    def selected(self) -> tuple[str, ...]:
        """Requested ids without repetitions, in the order first given."""
        return tuple(dict.fromkeys(self.molds))


@dataclass(frozen=True, slots=True)
class MoldResult:
    """One mold's run as the plugin judges it: the run's own verdicts, projected."""

    mold_id: str
    run_id: str
    exit_code: int
    findings: tuple[CiFinding, ...]
    resisted: int
    not_tested: int
    not_applicable: int

    @property
    def gated(self) -> tuple[CiFinding, ...]:
        return tuple(item for item in self.findings if item.effective_gated)

    def state(self) -> tuple[TestState, str]:
        """The pytest state and its reason code, from the native result alone."""
        if self.gated:
            return "failed", "gazua_new_gated_finding"
        if any(item.status == "open" for item in self.findings):
            return "xfailed", "gazua_known_finding"
        if self.findings:
            return "xfailed", "gazua_finding_not_gated"
        if self.resisted:
            return "passed", "gazua_resisted"
        if self.not_tested:
            return "skipped", "gazua_not_tested"
        return "skipped", "gazua_not_applicable"


def finding_line(item: CiFinding) -> str:
    """One finding as the plugin prints it: identifiers, enumerations and the command."""
    tool = item.tool if item.tool is not None else "no recorded tool"
    status = "no baseline" if item.status is None else ("known" if item.status == "open" else "new")
    if item.regression:
        status += ", regression"
    gate = "gated" if item.effective_gated else "not gated"
    line = f"Gazua finding {item.id}: {item.severity} {item.damage} in {tool} ({status}, {gate})."
    if item.reproduction is not None:
        line += f"\n  Reproduce: {' '.join(item.reproduction)}"
    return line


def describe(result: MoldResult, findings: tuple[CiFinding, ...]) -> str:
    lines = [finding_line(item) for item in findings]
    lines.append(f"Run {result.run_id}; reports in .gazua/report.html and .gazua/run.json.")
    return "\n".join(lines)
