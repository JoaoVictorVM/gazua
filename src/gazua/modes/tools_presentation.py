"""What tools mode prints: the inventory, the size of the run, the findings and how to reproduce.

Every sentence comes from a fixed template. Names come from the configuration or the target and
are sanitized before printing; tool returns, record ids and canary values are never printed.
Reproduction commands are quoted for the shell they are shown for, never concatenated.
"""

from __future__ import annotations

import os
import shlex
from collections.abc import Sequence
from typing import Final, Literal, TypeAlias

from gazua.diagnostics import sanitize
from gazua.modes.tools import NO_TOOL_CAN_RUN, ToolsPreview
from gazua.modes.tools_models import DiscoveredTool, SkipReason, ToolsDiagnostic, ToolsResult
from gazua.verdicts.models import AttackContext, AttackResult, Proof
from gazua.verdicts.presentation import DAMAGE_LABELS, summary_lines

Shell: TypeAlias = Literal["posix", "windows"]
SKIP_TEXT: Final[dict[SkipReason, str]] = {
    "missing_safe": "not tested, missing safe: true",
    "tool_not_found": "not tested, not registered when the test module was imported",
    "tool_name_conflict": "not tested, distinct functions share this name",
    "tool_unclassified": "not tested, missing sensitive or forbidden declaration",
}
LATE_REGISTRATION: Final = (
    "No tool was registered when the test module was imported. Register the tools at module "
    "level of the test entrypoint with gazua.wrap or @gazua.tool (docs/tools-mode.md)."
)
_WINDOWS_UNQUOTABLE: Final = frozenset('"%!')
_PLAIN: Final = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./:=")


def default_shell() -> Shell:
    return "windows" if os.name == "nt" else "posix"


def _windows_argument(argument: str) -> str | None:
    if any(char in _WINDOWS_UNQUOTABLE for char in argument):
        return None
    if argument and set(argument) <= _PLAIN | {"\\"}:
        return argument
    # Inside double quotes, backslashes are literal except before the closing quote.
    doubled = "\\" * (len(argument) - len(argument.rstrip("\\")))
    return '"' + argument + doubled + '"'


def render_command(arguments: Sequence[str], shell: Shell) -> str | None:
    """One command line that a shell splits back into ``arguments``; None when none is safe.

    Control characters cannot be written safely on one line, and cmd.exe cannot quote ``"``,
    ``%`` or ``!`` reliably, so those arguments get no command.
    """
    if any(not argument.isprintable() for argument in arguments):
        return None
    if shell == "posix":
        return shlex.join(arguments)
    rendered = [_windows_argument(argument) for argument in arguments]
    if any(item is None for item in rendered):
        return None
    return " ".join(item for item in rendered if item is not None)


def skip_text(tool: DiscoveredTool) -> str:
    reason = tool.skip_reason
    return "runs" if reason is None else SKIP_TEXT[reason]


def inventory_lines(preview: ToolsPreview) -> list[str]:
    """Printed before the first attack: tools, combinations, limit and concurrency."""
    inventory = preview.inventory
    runnable = [sanitize(tool.name) for tool in inventory.runnable]
    lines = [f"Tools under test: {', '.join(runnable) if runnable else 'none'}"]
    skipped = inventory.skipped
    if skipped:
        lines.append("Tools skipped:")
        lines.extend(f"  {sanitize(tool.name)}: {skip_text(tool)}" for tool in skipped)
    total = len(preview.plan.attacks)
    ready = len(preview.plan.requests)
    noun = "combination" if total == 1 else "combinations"
    lines.append(
        f"Attacks: {total} {noun}, {ready} to run once each, {total - ready} not runnable."
    )
    lines.append(
        f"Limit {preview.limits.max_runs} executions. Concurrency {preview.effective_concurrency}."
    )
    return lines


def _capitalized(text: str) -> str:
    return text[:1].upper() + text[1:]


def _what_happened(result: AttackResult, context: AttackContext, proof: Proof) -> str:
    tool = sanitize(context.tool_name or "the tool")
    signal = proof.signal
    if signal == "victim_record_access":
        index = proof.facts.get("record_index", context.record_index)
        return f"{tool} returned victim record #{index} when called by the attacker."
    if signal == "forbidden_tool_call":
        return f"{tool}, declared forbidden, ran when called directly."
    if signal == "sensitive_tool_call":
        return f"{tool}, declared sensitive, ran when called directly."
    if signal == "canary_in_response":
        return f"{tool} returned canary #{proof.canary_index}."
    if signal == "output_sink_effect":
        return "The output sink rendered Gazua's marker without neutralizing it."
    if signal == "tool_call_ceiling":
        return f"{tool} kept accepting calls until Gazua's ceiling stopped them."
    return f"{_capitalized(DAMAGE_LABELS[result.damage])} was observed."


def _proof_text(proof: Proof) -> str:
    parts: list[str] = []
    if proof.reference is not None:
        parts.append(sanitize(proof.reference))
    if proof.call_seq is not None:
        parts.append(f"call {proof.call_seq}")
    location = ", ".join(parts) if parts else "operational record"
    conditions = ", ".join(proof.conditions) if proof.conditions else "none"
    return f"Proof: {location}. Conditions: {conditions}."


def finding_lines(result: ToolsResult, shell: Shell) -> list[str]:
    contexts = {context.attack_key: context for context in result.contexts}
    lines: list[str] = []
    for item in result.verdicts.results:
        if item.state != "finding" or not item.proof:
            continue
        context = contexts[item.attack_key]
        proof = item.proof[0]
        damage = DAMAGE_LABELS[item.damage]
        gate = " Gated." if item.gated else ""
        lines.append(
            f"{_capitalized(item.severity)}: {damage}. {_what_happened(item, context, proof)}{gate}"
        )
        lines.append(f"  Mold: {sanitize(item.mold_id)}. {_proof_text(proof)}")
        arguments = result.reproduction.get(item.attack_key)
        command = render_command(arguments, shell) if arguments else None
        if command is not None:
            lines.append(f"  Reproduce: {command}")
        else:
            lines.append(
                f"  Reproduce: run gazua run --tools --mold {sanitize(item.mold_id)} with the "
                "same configuration."
            )
    return lines


def _diagnostic_text(diagnostic: ToolsDiagnostic) -> str | None:
    tool = sanitize(diagnostic.tool_name or "a tool")
    names = ", ".join(sanitize(name) for name in diagnostic.arguments)
    if diagnostic.code == "missing_tool_arguments":
        return f"Not tested: {tool} needs arguments the attack does not provide: {names}."
    if diagnostic.code == "arguments_not_accepted":
        return f"Not tested: {tool} does not accept the arguments: {names}."
    if diagnostic.code == "no_runnable_tool":
        return NO_TOOL_CAN_RUN
    if diagnostic.code == "no_tools_registered":
        return LATE_REGISTRATION
    return None


def diagnostic_lines(result: ToolsResult) -> list[str]:
    lines: list[str] = []
    for diagnostic in result.diagnostics:
        text = _diagnostic_text(diagnostic)
        if text is not None and text not in lines:
            lines.append(text)
    return lines


def result_lines(
    result: ToolsResult, *, shell: Shell | None = None, version: str | None = None
) -> list[str]:
    """The summary by damage, each finding with its proof and reproduction, and the problems."""
    chosen = shell if shell is not None else default_shell()
    lines = [sanitize(line) for line in summary_lines(result.verdicts, version=version)]
    lines.extend(finding_lines(result, chosen))
    lines.extend(diagnostic_lines(result))
    return lines
