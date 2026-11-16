"""One self-contained Markdown issue per finding, projected from a validated run document.

The projection is minimal by default: ids, typed conditions, per scenario rates and bounds, the
guide and the acceptance criteria. Proof excerpts, locators, tool arguments and returns,
reproduction arguments, conversations and fixtures never enter it. Free text that came from the
configuration, the catalog or the target is masked again here, with no exception for declared
synthetic data, and then escaped or fenced by the template. Only ``include_attack`` adds the
attack description and payload of each scenario, in literal blocks marked as untrusted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cache
from importlib.resources import files
from typing import Any, Final

from pydantic import JsonValue

from gazua.issues.models import IssueFile
from gazua.reports.fixes import fix_anchor
from gazua.reports.guide_models import GUIDE_CATEGORIES, GuideEntry
from gazua.reports.models import RunDocument
from gazua.reports.rendering import (
    baseline_label,
    commands_for,
    issue_file_name,
    markdown_environment,
    verify_argv,
)
from gazua.verdicts.presentation import DAMAGE_LABELS, rate_text

ISSUE_TEMPLATE_VERSION: Final = 1
_FINDING_ID: Final = re.compile(r"^finding-[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class ScenarioLine:
    key: str
    rate: str
    coverage: str


@dataclass(frozen=True, slots=True)
class AttackBlock:
    key: str
    attack: str
    payload: JsonValue


@dataclass(frozen=True, slots=True)
class IssueView:
    title: str
    finding_id: str
    run_id: str
    mode: str
    severity: str
    gated: bool
    damage: str
    damage_label: str
    mold: str
    tool: str | None
    baseline: str | None
    conditions: tuple[str, ...]
    scenarios: tuple[ScenarioLine, ...]
    proofs: tuple[tuple[str, str, str], ...]
    reproduction_available: bool
    reproduction_reason: str | None
    guide: GuideEntry
    guide_revision: int
    guide_fallback: bool
    guide_anchor: str
    categories: tuple[tuple[str, tuple[str, ...]], ...]
    confirm: tuple[tuple[str, str], ...]
    attacks: tuple[AttackBlock, ...] | None


def export_redactor() -> Any:
    """Masking with no synthetic exceptions: an issue leaves the project's local folder."""
    from gazua.reports.redaction import ReportRedactionPolicy, ReportRedactor

    return ReportRedactor(ReportRedactionPolicy(enabled=True))


def project(document: RunDocument, finding_id: str, *, include_attack: bool) -> IssueView:
    finding = next(item for item in document.findings if item.id == finding_id)
    redactor = export_redactor()
    results = {item.attack_key: item for item in document.verdicts.results}
    observed = {
        item.finding_id: item
        for item in (document.baseline.observed if document.baseline is not None else [])
    }
    entry = observed.get(finding.id)
    guide = document.guide.entry(finding.fix_ref)
    attacks = None
    if include_attack:
        attacks = tuple(
            AttackBlock(
                key=redactor.mask(key),
                attack=redactor.text(document.scenario(key).attack, "issues.attack"),
                payload=redactor.data(document.scenario(key).payload, "issues.payload"),
            )
            for key in finding.scenarios
        )
    label = DAMAGE_LABELS[finding.damage]
    return IssueView(
        title=f"{finding.severity.capitalize()}: {label}",
        finding_id=finding.id,
        run_id=document.run_id,
        mode=finding.mode,
        severity=finding.severity,
        gated=finding.gated,
        damage=finding.damage,
        damage_label=label,
        mold=redactor.mask(finding.mold_id),
        tool=None if finding.tool_name is None else redactor.mask(finding.tool_name),
        baseline=None if entry is None else baseline_label(entry),
        conditions=tuple(finding.conditions),
        scenarios=tuple(
            ScenarioLine(redactor.mask(key), rate_text(results[key]), results[key].coverage)
            for key in finding.scenarios
        ),
        proofs=tuple(
            (proof.id, proof.source, proof.execution_id)
            for proof in document.proofs
            if proof.id in finding.proof_ids
        ),
        reproduction_available=finding.reproduction.available,
        reproduction_reason=finding.reproduction.reason,
        guide=guide,
        guide_revision=document.guide.revision,
        guide_fallback=document.guide.origin != "captured",
        guide_anchor=fix_anchor(finding.fix_ref),
        categories=tuple((title, tuple(getattr(guide, name))) for name, title in GUIDE_CATEGORIES),
        confirm=commands_for(verify_argv(finding)),
        attacks=attacks,
    )


@cache
def _template() -> Any:
    source = files("gazua").joinpath("issues/templates/issue.md.j2").read_text(encoding="utf-8")
    return markdown_environment().from_string(source)


def render_issue(document: RunDocument, finding_id: str, *, include_attack: bool = False) -> str:
    """The Markdown of one finding's issue. Deterministic for the same document and template."""
    view = project(document, finding_id, include_attack=include_attack)
    return _template().render(issue=view, template_version=ISSUE_TEMPLATE_VERSION)


def render_issues(document: RunDocument, *, include_attack: bool = False) -> list[IssueFile]:
    """One file per finding, ordered by the full finding id."""
    rendered: list[IssueFile] = []
    for finding in sorted(document.findings, key=lambda item: item.id):
        # Validated by the document already; the file name must never depend on anything else.
        if not _FINDING_ID.fullmatch(finding.id):
            raise ValueError("finding id")
        rendered.append(
            IssueFile(
                issue_file_name(finding),
                render_issue(document, finding.id, include_attack=include_attack),
            )
        )
    return rendered
