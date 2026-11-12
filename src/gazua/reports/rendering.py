"""HTML, Markdown and terminal presentations of a run document.

Rendering is pure: it reads only the validated document and the packaged templates and assets,
never the evidence files, the configuration or the target. The same document and templates give
the same bytes, so no clock, absolute path or new id is written. Every value from the document
is untrusted: HTML autoescapes it, Markdown escapes it or fences it as a literal block, and the
terminal strips control sequences.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import string
from collections.abc import Sequence
from dataclasses import dataclass
from functools import cache
from importlib.resources import files
from typing import Any, Final

from gazua.catalog.models import DAMAGES, Damage
from gazua.reports.fixes import fix_anchor
from gazua.reports.models import Finding, ProofSnapshot, RunDocument, Scenario
from gazua.reports.terminal import clean_terminal
from gazua.verdicts.models import VERDICT_STATES, AttackResult, VerdictState
from gazua.verdicts.presentation import (
    DAMAGE_LABELS,
    NOT_REPORTED,
    STATE_LABELS,
    rate_text,
    reason_text,
    state_text,
    summary_lines,
)

TEMPLATE_VERSION: Final = 1
NO_REDACT_WARNING: Final = (
    "Warning: masking was disabled locally with --no-redact. This report may contain secrets "
    "and personal data; do not share or commit it."
)
SECTIONS: Final[tuple[tuple[VerdictState, str, str], ...]] = (
    ("conditional_risk", "Conditional risks, not verified", "conditional"),
    ("resisted", "Resisted", "resisted"),
    ("not_applicable", "Not applicable", "not-applicable"),
    ("not_tested", "Not tested", "not-tested"),
)
_MARKDOWN_ENTITIES: Final = {"<": "&lt;", ">": "&gt;", "&": "&amp;"}
_PUNCTUATION: Final = frozenset(string.punctuation)


def _asset(name: str) -> str:
    return files("gazua").joinpath(f"reports/{name}").read_text(encoding="utf-8")


def csp_hash(content: str) -> str:
    digest = hashlib.sha256(content.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def content_security_policy(style: str, script: str) -> str:
    return (
        "default-src 'none'; base-uri 'none'; form-action 'none'; connect-src 'none'; "
        f"object-src 'none'; img-src 'none'; style-src {csp_hash(style)}; "
        f"script-src {csp_hash(script)}"
    )


def markdown_inline(value: object) -> str:
    """Untrusted text as inert Markdown on one line: no markup, links, HTML or table cells."""
    text = clean_terminal(str(value)).replace("\n", " ").replace("\t", " ")
    out: list[str] = []
    for char in text:
        if char in _MARKDOWN_ENTITIES:
            out.append(_MARKDOWN_ENTITIES[char])
        elif char in _PUNCTUATION:
            out.append("\\" + char)
        else:
            out.append(char)
    return "".join(out)


def markdown_block(value: object, info: str = "text") -> str:
    """A fenced literal block longer than any backtick run inside it."""
    text = clean_terminal(value if isinstance(value, str) else pretty_json(value))
    runs = [len(item) for item in re.findall(r"`+", text)]
    fence = "`" * max(3, max(runs, default=0) + 1)
    return f"{fence}{info}\n{text}\n{fence}"


def pretty_json(value: object) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True, allow_nan=False)


@dataclass(frozen=True, slots=True)
class ScenarioView:
    scenario: Scenario
    result: AttackResult

    @property
    def state_label(self) -> str:
        return state_text(self.result)

    @property
    def rate(self) -> str:
        return rate_text(self.result)

    @property
    def reasons(self) -> list[str]:
        return [reason_text(item) for item in self.result.reasons]


@dataclass(frozen=True, slots=True)
class FindingView:
    finding: Finding
    scenarios: tuple[ScenarioView, ...]
    proofs: tuple[ProofSnapshot, ...]
    commands: tuple[tuple[str, str], ...]

    @property
    def damage_label(self) -> str:
        return DAMAGE_LABELS[self.finding.damage]


@dataclass(frozen=True, slots=True)
class LowGroup:
    """Low findings of one damage and tool, shown together. Each keeps its id and proofs."""

    damage: Damage
    tool_name: str | None
    findings: tuple[FindingView, ...]

    @property
    def label(self) -> str:
        return DAMAGE_LABELS[self.damage]

    @property
    def gated(self) -> bool:
        return any(item.finding.gated for item in self.findings)


def commands_for(argv: Sequence[str]) -> tuple[tuple[str, str], ...]:
    from gazua.modes.tools_presentation import render_command

    found: list[tuple[str, str]] = []
    for label, shell in (
        ("POSIX shell", "posix"),
        ("PowerShell", "powershell"),
        ("cmd.exe", "windows"),
    ):
        rendered = render_command(argv, shell)  # type: ignore[arg-type]
        if rendered is not None:
            found.append((label, rendered))
    return tuple(found)


def presentation_groups(views: Sequence[FindingView]) -> list[FindingView | LowGroup]:
    """Findings in document order, with low ones of the same damage and tool grouped."""
    groups: dict[tuple[Damage, str | None], list[FindingView]] = {}
    for view in views:
        if view.finding.severity == "low":
            groups.setdefault((view.finding.damage, view.finding.tool_name), []).append(view)
    shown: list[FindingView | LowGroup] = []
    placed: set[tuple[Damage, str | None]] = set()
    for view in views:
        key = (view.finding.damage, view.finding.tool_name)
        if view.finding.severity != "low" or len(groups[key]) == 1:
            shown.append(view)
        elif key not in placed:
            placed.add(key)
            shown.append(LowGroup(key[0], key[1], tuple(groups[key])))
    return shown


@dataclass(frozen=True, slots=True)
class ReportView:
    document: RunDocument
    findings: tuple[FindingView, ...]
    groups: tuple[FindingView | LowGroup, ...]
    sections: tuple[tuple[str, str, str, tuple[ScenarioView, ...]], ...]
    damage_rows: tuple[tuple[Damage, str, dict[str, int], int], ...]
    totals: dict[str, int]


def build_view(document: RunDocument) -> ReportView:
    results = {item.attack_key: item for item in document.verdicts.results}
    views = {
        item.attack_key: ScenarioView(item, results[item.attack_key]) for item in document.scenarios
    }
    snapshots = {item.id: item for item in document.proofs}
    findings = tuple(
        FindingView(
            finding=item,
            scenarios=tuple(views[key] for key in item.scenarios),
            proofs=tuple(snapshots[key] for key in item.proof_ids),
            commands=commands_for(item.reproduction.argv) if item.reproduction.available else (),
        )
        for item in document.findings
    )
    sections = tuple(
        (state, title, anchor, tuple(view for view in views.values() if view.result.state == state))
        for state, title, anchor in SECTIONS
    )
    rows: list[tuple[Damage, str, dict[str, int], int]] = []
    for damage in DAMAGES:
        counts = document.verdicts.counts_by_damage.get(damage)
        if counts is None:
            continue
        gated = sum(item.gated for item in document.verdicts.results if item.damage == damage)
        rows.append(
            (damage, DAMAGE_LABELS[damage], {s: getattr(counts, s) for s in VERDICT_STATES}, gated)
        )
    totals = {
        state: sum(item.state == state for item in document.verdicts.results)
        for state in VERDICT_STATES
    }
    return ReportView(
        document, findings, tuple(presentation_groups(findings)), sections, tuple(rows), totals
    )


@cache
def _environment(markdown: bool) -> Any:
    from jinja2 import BaseLoader, Environment, StrictUndefined

    environment = Environment(
        loader=BaseLoader(),
        # Markdown escapes each value with its own filters; HTML autoescapes everything.
        autoescape=not markdown,  # noqa: S701
        undefined=StrictUndefined,
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    environment.filters.update(
        clean=lambda value: clean_terminal(str(value)),
        pretty=pretty_json,
        md=markdown_inline,
        block=markdown_block,
    )
    return environment


def _context(document: RunDocument) -> dict[str, Any]:
    metadata = document.metadata
    return {
        "view": build_view(document),
        "doc": document,
        "meta": metadata,
        "not_reported": NOT_REPORTED,
        "state_labels": STATE_LABELS,
        "states": VERDICT_STATES,
        "damages": DAMAGES,
        "damage_labels": DAMAGE_LABELS,
        "fix_anchor": fix_anchor,
        "no_redact_warning": NO_REDACT_WARNING if document.redaction == "none" else None,
        "template_version": TEMPLATE_VERSION,
    }


def render_html(document: RunDocument) -> str:
    style, script = _asset("assets/report.css"), _asset("assets/report.js")
    template = _environment(False).from_string(_asset("templates/report.html.j2"))
    return template.render(
        **_context(document),
        style=style,
        script=script,
        csp=content_security_policy(style, script),
    )


def render_markdown(document: RunDocument) -> str:
    template = _environment(True).from_string(_asset("templates/report.md.j2"))
    return template.render(**_context(document))


def render_report(document: RunDocument) -> tuple[str, str]:
    """The HTML and Markdown of the document. Deterministic for the same templates."""
    return render_html(document), render_markdown(document)


def terminal_lines(document: RunDocument, *, shell: str | None = None) -> list[str]:
    """The summary by damage and state, then each finding with conditions, command and fix."""
    from gazua.modes.tools_presentation import default_shell, render_command

    chosen = shell or default_shell()
    if chosen == "windows":
        chosen = "powershell"
    lines: list[str] = []
    if document.redaction == "none":
        lines.append(NO_REDACT_WARNING)
    metadata = document.metadata
    lines.extend(
        summary_lines(document.verdicts, version=metadata.gazua_version, model=metadata.model)
    )
    snapshots = {item.id: item for item in document.proofs}
    for finding in document.findings:
        damage = DAMAGE_LABELS[finding.damage]
        gate = " Gated." if finding.gated else ""
        attack = " ".join(finding.attack.split())
        lines.append(f"{finding.severity.capitalize()}: {damage}. {attack}{gate}")
        lines.append(f"  Finding: {finding.id}. Mold: {finding.mold_id}.")
        conditions = ", ".join(finding.conditions) if finding.conditions else "none"
        lines.append(f"  Conditions: {conditions}.")
        for proof_id in finding.proof_ids:
            snapshot = snapshots[proof_id]
            note = (
                f" Excerpt missing: {snapshot.omission_reason.replace('_', ' ')}."
                if snapshot.omission_reason
                else (" Excerpt truncated." if snapshot.truncated else "")
            )
            lines.append(f"  Proof {snapshot.id}: {snapshot.source}.{note}")
        command = (
            render_command(finding.reproduction.argv, chosen)  # type: ignore[arg-type]
            if finding.reproduction.available
            else None
        )
        if command is not None:
            lines.append(f"  Reproduce: {command}")
        else:
            reason = (finding.reproduction.reason or "not_reproducible").replace("_", " ")
            lines.append(
                f"  Reproduce: unavailable ({reason}); run gazua run --tools --mold "
                f"{finding.mold_id} with the same configuration."
            )
        lines.append(f"  Fix ({fix_anchor(finding.damage)}): {finding.fix}")
    for diagnostic in document.diagnostics:
        where = f" ({diagnostic.field})" if diagnostic.field else ""
        lines.append(f"Report {diagnostic.level}: {diagnostic.code.replace('_', ' ')}{where}.")
    return [clean_terminal(line) for line in lines]
