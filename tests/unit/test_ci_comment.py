from typing import Any

import pytest
from ci_support import plain_run

from gazua.ci.comment import headline, render_comment
from gazua.ci.models import COMMENT_MARKER, CommentCounts, CommentDocument, CommentFinding
from gazua.ci.projection import comment_document, project

ORDER = ["critical", "high", "medium", "low"]


def _finding(index: int, severity: str = "high", **extra: Any) -> CommentFinding:
    data: dict[str, Any] = {
        "id": "finding-" + f"{index:064x}",
        "severity": severity,
        "damage": "idor_via_agent",
        "tool": "get_order",
        "status": None,
        "regression": False,
        "reproduction": ["gazua", "run", "--tools", "--config", "gazua.yaml", "--mold", "idor-01"],
    }
    data.update(extra)
    return CommentFinding.model_validate(data)


def _document(findings: list[CommentFinding], not_tested: int = 0) -> CommentDocument:
    return CommentDocument(
        schema_version=1,
        run_id="GAZUA-run-1",
        exit_code=1 if findings else 0,
        counts=CommentCounts(new=len(findings), known=0, not_tested=not_tested),
        findings=findings,
    )


def test_comment_has_v1_marker_and_stable_order() -> None:
    severities = ["low", "critical", "medium", "high"]
    findings = sorted(
        (_finding(index, level) for index, level in enumerate(severities, start=1)),
        key=lambda item: (ORDER.index(item.severity), item.id),
    )

    body = render_comment(_document(findings, not_tested=4))

    assert body.startswith(COMMENT_MARKER + "\n## Gazua security tests\n")
    rows = [line for line in body.splitlines() if line.startswith("| ") and "`finding-" in line]
    assert [row.split(" | ")[0].removeprefix("| ") for row in rows] == ORDER
    assert "**4 new findings (1 critical, 1 high, 1 medium, 1 low), 0 known, 4 not tested**" in body
    assert "not a certificate" in body
    assert "`gazua run --tools --config gazua.yaml --mold idor-01`" in body


def test_headline_matches_the_experience() -> None:
    one = _document([_finding(1)], not_tested=4)
    known = CommentDocument(
        schema_version=1,
        run_id="GAZUA-run-1",
        exit_code=0,
        counts=CommentCounts(new=0, known=2, not_tested=4),
        findings=[_finding(1, status="open"), _finding(2, status="open")],
    )

    assert headline(one) == "1 new high finding, 0 known, 4 not tested"
    assert headline(known) == "0 new findings, 2 known, 4 not tested"


def test_comment_updates_same_bytes_deterministically() -> None:
    first = render_comment(comment_document(project(plain_run())))
    second = render_comment(comment_document(project(plain_run())))

    assert first.encode("utf-8") == second.encode("utf-8")


def test_comment_truncates_at_item_boundary() -> None:
    findings = [_finding(index) for index in range(1, 400)]

    body = render_comment(_document(findings), limit=8 * 1024)

    assert len(body.encode("utf-8")) <= 8 * 1024
    assert body.startswith(COMMENT_MARKER)
    assert "**399 new high findings, 0 known, 0 not tested**" in body
    shown = [line for line in body.splitlines() if line.startswith("| high |")]
    assert 0 < len(shown) < 399
    assert f"{399 - len(shown)} more findings omitted; see the local report." in body
    assert shown[0].endswith(f"`{findings[0].id}` |")
    reproduced = [line for line in body.splitlines() if line.startswith("- `finding-")]
    assert len(reproduced) == len(shown)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tool", "x|y<script>"),
        ("tool", "a\x1b[31m"),
        ("reproduction", ["gazua", "run", "--tools", "--mold", "[a](http://x)"]),
        ("reproduction", ["gazua", "run", "--tools", "--mold", "a`b"]),
    ],
)
def test_markdown_and_controls_are_inert(field: str, value: Any) -> None:
    with pytest.raises(ValueError, match="pattern"):
        _finding(1, **{field: value})

    body = render_comment(_document([_finding(1)]))

    assert "\x1b" not in body
    for line in body.splitlines():
        if line.startswith("| high"):
            assert line.count("|") == 6
