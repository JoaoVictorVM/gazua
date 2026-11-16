import re

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from report_factory import FOUND, document

from gazua.issues.rendering import render_issues
from gazua.reports.models import RunDocument

BASE = document()
HOSTILE = st.one_of(
    st.text(min_size=1, max_size=60),
    st.sampled_from(
        [
            "```\n# Heading\n<script>x</script>\n````",
            "[x](https://evil.example) | <img src=x onerror=1>",
            "\x1b[31mred\x1b[0m\x07\r\n## Injected",
            "../../outside/../file.md",
            "..\\..\\windows\\system32",
            "<!-- comment --> *bold* _it_ `code`",
        ]
    ),
)


def _hostile(text: str) -> RunDocument:
    [finding] = BASE.findings
    scenarios = [
        item.model_copy(update={"attack": text, "payload": {"value": text}})
        if item.attack_key == FOUND
        else item
        for item in BASE.scenarios
    ]
    changed = finding.model_copy(update={"mold_id": text, "tool_name": text, "attack": text})
    return BASE.model_copy(update={"findings": [changed], "scenarios": scenarios})


def _outside_fences(markdown: str) -> list[str]:
    kept: list[str] = []
    fence: str | None = None
    for line in markdown.splitlines():
        opening = re.match(r"^(`{3,})", line)
        if fence is None and opening:
            fence = opening.group(1)
        elif fence is not None and line == fence:
            fence = None
        elif fence is None:
            kept.append(line)
    assert fence is None
    return kept


HEADINGS = [
    line
    for line in _outside_fences(render_issues(_hostile("plain"), include_attack=True)[0].content)
    if line.startswith("#")
]


@settings(max_examples=60, deadline=None)
@given(HOSTILE)
def test_arbitrary_text_remains_inert(text: str) -> None:
    [issue] = render_issues(_hostile(text), include_attack=True)
    outside = _outside_fences(issue.content)

    assert "\x1b" not in issue.content
    assert "\x07" not in issue.content
    assert [line for line in outside if line.startswith("#")] == HEADINGS
    assert not any("](" in line for line in outside)
    assert [line for line in outside if "<" in line] == [outside[-1]]
    assert outside[-1] == "<!-- gazua-issue 1 -->"


@settings(max_examples=40, deadline=None)
@given(HOSTILE)
def test_filename_depends_only_on_validated_id(text: str) -> None:
    [issue] = render_issues(_hostile(text), include_attack=True)

    assert issue.name == f"{BASE.findings[0].id}.md"
    assert re.fullmatch(r"finding-[0-9a-f]{64}\.md", issue.name)


def test_invalid_id_never_names_a_file() -> None:
    [finding] = BASE.findings
    broken = BASE.model_copy(
        update={"findings": [finding.model_copy(update={"id": "../../finding-x"})]}
    )

    with pytest.raises(ValueError, match="finding id"):
        render_issues(broken)
