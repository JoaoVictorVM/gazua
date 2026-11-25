"""The allowlist projection of a validated run document. No I/O, no configuration, no target.

Only identifiers, enumerations, counts and the checked reproduction command leave the run.
Attack text, payloads, conversations, proofs, snapshots, arguments, returns, canaries,
fixtures, the target reference and free error messages never do, whatever the redaction mode.
"""

from __future__ import annotations

from typing import Final

from pydantic import ValidationError

from gazua.ci.models import (
    MAX_FINDINGS,
    MAX_REPRODUCTION_TOKENS,
    SEVERITY_RANK,
    TOKEN,
    TOOL_NAME,
    CiFinding,
    CiSummary,
    CommentCounts,
    CommentDocument,
    CommentFinding,
)
from gazua.diagnostics import looks_like_secret
from gazua.reports.models import Finding, RunDocument
from gazua.reports.terminal import clean_terminal

TOOL_OMITTED: Final = "ci_tool_name_omitted"
REPRODUCTION_OMITTED: Final = "ci_reproduction_omitted"
_VERSION_LIMIT: Final = 128


class ProjectionError(Exception):
    """The run cannot produce the minimal contract. ``code`` is safe to print."""

    def __init__(self, code: str = "ci_projection_invalid") -> None:
        self.code = code
        super().__init__(code)


def safe_tool(name: str | None) -> tuple[str | None, bool]:
    """The tool name when every treatment passes, else None; the flag says it was omitted."""
    if name is None:
        return None, False
    cleaned = clean_terminal(name)
    if cleaned != name or looks_like_secret(name) or not TOOL_NAME.fullmatch(name):
        return None, True
    return name, False


def safe_reproduction(finding: Finding) -> tuple[list[str] | None, bool]:
    """The command tokens when available and inert, else None; the flag says it was omitted."""
    command = finding.reproduction
    if not command.available or command.cwd != ".":
        return None, command.available
    tokens = list(command.argv)
    if (
        len(tokens) > MAX_REPRODUCTION_TOKENS
        or tokens[:3] != ["gazua", "run", f"--{finding.mode}"]
        or any(not TOKEN.fullmatch(item) or looks_like_secret(item) for item in tokens)
    ):
        return None, True
    return tokens, False


def _version(value: str | None) -> str | None:
    if value is None or len(value) > _VERSION_LIMIT:
        return None
    return value if TOKEN.fullmatch(value) else None


def project(document: RunDocument) -> CiSummary:
    """The CI summary of a run. Inconsistent comparisons raise ``ProjectionError``."""
    if document.verification is not None:
        raise ProjectionError
    if len(document.findings) > MAX_FINDINGS:
        raise ProjectionError("ci_too_many_findings")
    comparison = document.baseline
    observed = {} if comparison is None else {item.finding_id: item for item in comparison.observed}
    if comparison is not None and set(observed) != {item.id for item in document.findings}:
        raise ProjectionError
    diagnostics: set[str] = set()
    findings: list[CiFinding] = []
    for finding in document.findings:
        tool, tool_omitted = safe_tool(finding.tool_name)
        command, command_omitted = safe_reproduction(finding)
        if tool_omitted:
            diagnostics.add(TOOL_OMITTED)
        if command_omitted:
            diagnostics.add(REPRODUCTION_OMITTED)
        entry = observed.get(finding.id)
        if entry is not None and entry.native_gated != finding.gated:
            raise ProjectionError
        findings.append(
            CiFinding(
                id=finding.id,
                severity=finding.severity,
                damage=finding.damage,
                mode=finding.mode,
                tool=tool,
                status=None if entry is None else ("open" if entry.status == "open" else "new"),
                regression=False if entry is None else entry.regression,
                effective_gated=finding.gated if entry is None else entry.effective_gated,
                reproduction=command,
            )
        )
    findings.sort(key=lambda item: (SEVERITY_RANK[item.severity], item.id))
    states = [item.state for item in document.verdicts.results]
    new = sum(item.status in (None, "new") for item in findings)
    try:
        return CiSummary(
            schema_version=1,
            run_id=document.run_id,
            gazua_version=_version(document.metadata.gazua_version),
            mode=document.metadata.mode,
            effective_exit_code=document.report_exit_code,
            baseline=comparison is not None,
            new_findings=new,
            known_findings=sum(item.status == "open" for item in findings),
            not_tested=states.count("not_tested"),
            not_applicable=states.count("not_applicable"),
            findings=findings,
            diagnostics=sorted(diagnostics),
        )
    except ValidationError:
        raise ProjectionError from None


def comment_document(summary: CiSummary) -> CommentDocument:
    """The pull request comment's data, validated as ``pr-comment-v1``."""
    try:
        return CommentDocument(
            schema_version=1,
            run_id=summary.run_id,
            exit_code=summary.effective_exit_code,
            counts=CommentCounts(
                new=summary.new_findings,
                known=summary.known_findings,
                not_tested=summary.not_tested,
            ),
            findings=[
                CommentFinding(
                    id=item.id,
                    severity=item.severity,
                    damage=item.damage,
                    tool=item.tool,
                    status=item.status,
                    regression=item.regression,
                    reproduction=item.reproduction,
                )
                for item in summary.findings
            ],
        )
    except ValidationError:
        raise ProjectionError("ci_comment_invalid") from None
