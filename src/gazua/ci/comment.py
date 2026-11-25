"""The pull request comment as stable, bounded Markdown.

Every value written here comes from ``pr-comment-v1``: identifiers, enumerations, counts and
tokens restricted to inert characters, always inside code spans. The same document always
gives the same bytes, so an unchanged run never edits the comment.
"""

from __future__ import annotations

from typing import Final

from gazua.ci.models import (
    COMMENT_LIMIT_BYTES,
    COMMENT_MARKER,
    SEVERITY_RANK,
    CommentDocument,
    CommentFinding,
)

HEADER: Final = "## Gazua security tests"
DOCS_URL: Final = "https://github.com/JoaoVictorVM/gazua/blob/main/docs/ci.md"
REPORTS: Final = ("`.gazua/report.html`", "`.gazua/report.md`", "`.gazua/run.json`")
FLOOR_NOTE: Final = (
    "Passing means none of the molds that ran proved an effect. It is a floor, not a "
    "certificate: untested and not applicable scenarios prove nothing."
)
_GATE: Final[dict[int, str]] = {
    0: "Gate: passed.",
    1: "Gate: failed, a new gated finding.",
    2: "Gate: failed, an operational error (exit 2). Results may be incomplete.",
}


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def headline(document: CommentDocument) -> str:
    """The summary line, for example ``1 new high finding, 2 known, 4 not tested``."""
    counts = document.counts
    new = [item for item in document.findings if item.status in (None, "new")]
    severities = sorted({item.severity for item in new}, key=lambda item: SEVERITY_RANK[item])
    if len(severities) == 1:
        first = _plural(counts.new, f"new {severities[0]} finding")
    else:
        first = _plural(counts.new, "new finding")
        if severities:
            parts = [
                f"{sum(item.severity == level for item in new)} {level}" for level in severities
            ]
            first += f" ({', '.join(parts)})"
    return f"{first}, {counts.known} known, {counts.not_tested} not tested"


def _status(item: CommentFinding) -> str:
    if item.status is None:
        return "no baseline"
    if item.status == "open":
        return "known"
    return "new, regression" if item.regression else "new"


def _row(item: CommentFinding) -> str:
    tool = f"`{item.tool}`" if item.tool is not None else "not recorded"
    return f"| {item.severity} | `{item.damage}` | {tool} | {_status(item)} | `{item.id}` |"


def _reproduction(item: CommentFinding) -> str:
    if item.reproduction is None:
        return f"- `{item.id}`: not available, see the local report"
    return f"- `{item.id}`: `{' '.join(item.reproduction)}`"


def _render(document: CommentDocument, shown: int) -> str:
    lines = [COMMENT_MARKER, HEADER, "", f"**{headline(document)}**", "", _GATE[document.exit_code]]
    findings = document.findings[:shown]
    if findings:
        lines += ["", "| Severity | Damage | Tool | Status | Finding |", "|---|---|---|---|---|"]
        lines += [_row(item) for item in findings]
        lines += ["", "Reproduce locally:", ""]
        lines += [_reproduction(item) for item in findings]
    omitted = len(document.findings) - shown
    if omitted:
        lines += ["", f"{_plural(omitted, 'more finding')} omitted; see the local report."]
    lines += [
        "",
        FLOOR_NOTE,
        "",
        f"Local reports: {', '.join(REPORTS)}. Run `{document.run_id}`. [About this "
        f"comment]({DOCS_URL})",
        "",
    ]
    return "\n".join(lines)


def render_comment(document: CommentDocument, limit: int = COMMENT_LIMIT_BYTES) -> str:
    """The comment body. Over ``limit`` UTF-8 bytes, the least severe findings are omitted."""
    total = len(document.findings)
    full = _render(document, total)
    if len(full.encode("utf-8")) <= limit:
        return full
    low, high = 0, total
    while low < high:
        middle = (low + high + 1) // 2
        if len(_render(document, middle).encode("utf-8")) <= limit:
            low = middle
        else:
            high = middle - 1
    return _render(document, low)
