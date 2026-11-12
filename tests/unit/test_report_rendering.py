import re
from html.parser import HTMLParser
from importlib.resources import files
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st
from report_factory import CONDITIONAL, document, five_states, victim_order

from gazua.catalog.models import DAMAGES
from gazua.reports.builder import PlainTreatment
from gazua.reports.rendering import (
    csp_hash,
    markdown_block,
    markdown_inline,
    render_report,
    terminal_lines,
)
from gazua.verdicts.presentation import STATE_LABELS

XSS = [
    "<script>window.pwned=1</script>",
    '"><img src=x onerror=alert(1)>',
    "<svg onload=alert(1)>",
    "</pre></article><script>alert(2)</script>",
    "javascript:alert(3)",
    "<a href='https://evil.example/x'>x</a>",
    "<style>body{background:url(https://evil.example)}</style>",
]


class Tags(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.data: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))

    def handle_data(self, data: str) -> None:
        self.data.append(data)


def parsed(html: str) -> Tags:
    parser = Tags()
    parser.feed(html)
    return parser


def hostile_document(**extra: Any) -> Any:
    kept = _kept_everything()
    return document(
        five_states(found_return=victim_order(note=" ".join(XSS), **extra)),
        on_evidence=kept,
        excerpts=kept,
    )


def _kept_everything() -> Any:
    from verdict_factory import config

    from gazua.reports.capture import ReportEvidenceCollector
    from gazua.reports.redaction import ReportRedactionPolicy, ReportRedactor

    return ReportEvidenceCollector(ReportRedactor(ReportRedactionPolicy.from_config(config())))


def test_all_five_states_and_reasons_are_visible() -> None:
    html, markdown = render_report(document())

    for text in (html, markdown):
        for title in ("Findings", "Conditional risks", "Resisted", "Not applicable", "Not tested"):
            assert title in text
        assert "receiver unavailable" in text
        assert "no applicable tool" in text
        assert "missing output sink" in text
    for state in STATE_LABELS.values():
        assert state in html


def test_empty_sections_are_still_shown() -> None:
    built = document()
    html, markdown = render_report(built.model_copy(update={"findings": [], "proofs": []}))

    assert "No verified finding." in html
    assert "Findings (0)" in markdown


def test_conditional_risk_is_not_a_finding() -> None:
    built = document()
    html, _ = render_report(built)
    findings = html.split('id="findings-title"')[1].split('id="conditional"')[0]

    assert CONDITIONAL not in findings
    assert CONDITIONAL in html.split('id="conditional"')[1]


def test_all_six_fixes_have_local_anchor() -> None:
    html, markdown = render_report(document())

    for damage in DAMAGES:
        assert f'id="fix-{damage}"' in html
        assert f'<a id="fix-{damage}"></a>' in markdown
    assert 'href="#fix-idor_via_agent"' in html
    assert "](#fix-idor_via_agent)" in markdown
    assert "gazua verify" not in html + markdown
    assert "http" not in re.sub(r'"https://raw[^"]*"', "", markdown)


def test_html_escapes_every_untrusted_context() -> None:
    built = hostile_document()
    html, _ = render_report(built)
    tree = parsed(html)

    tags = {tag for tag, _ in tree.tags}
    assert "img" not in tags
    assert "svg" not in tags
    assert [tag for tag, _ in tree.tags].count("script") == 1
    assert [tag for tag, _ in tree.tags].count("style") == 1
    assert not any(name.startswith("on") for _, attrs in tree.tags for name in attrs)
    hrefs = [attrs.get("href") or "" for tag, attrs in tree.tags if tag == "a"]
    assert all(href.startswith("#") for href in hrefs)
    assert "&lt;script&gt;window.pwned=1&lt;/script&gt;" in html


def test_csp_hashes_match_packaged_assets() -> None:
    html, _ = render_report(document())
    style = files("gazua").joinpath("reports/assets/report.css").read_text(encoding="utf-8")
    script = files("gazua").joinpath("reports/assets/report.js").read_text(encoding="utf-8")
    tree = parsed(html)
    policy = next(
        attrs["content"]
        for tag, attrs in tree.tags
        if tag == "meta" and attrs.get("http-equiv") == "Content-Security-Policy"
    )

    assert html.index("Content-Security-Policy") < html.index("<style>")
    assert policy is not None
    for directive in (
        "default-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "connect-src 'none'",
        "object-src 'none'",
        "img-src 'none'",
        f"style-src {csp_hash(style)}",
        f"script-src {csp_hash(script)}",
    ):
        assert directive in policy
    assert f"<style>{style}</style>" in html
    assert f"<script>{script}</script>" in html
    assert "innerHTML" not in script
    assert "eval(" not in script


def test_markdown_cannot_escape_literal_block() -> None:
    hostile = "```\n# Heading\n<script>x</script>\n````"
    block = markdown_block(hostile)
    fence = block.split("\n")[0]

    assert fence.startswith("`````")
    assert block.endswith("\n" + fence[: len(fence) - len("text")])
    assert markdown_inline("[x](https://evil.example) | <b>") == (
        "\\[x\\]\\(https\\:\\/\\/evil\\.example\\) \\| &lt;b&gt;"
    )
    _, markdown = render_report(hostile_document())
    outside = outside_fences(markdown)
    assert "<script>" in markdown
    assert "<script>" not in outside
    assert "<img" not in outside
    assert "](https://evil" not in outside


def outside_fences(markdown: str) -> str:
    """The Markdown with every fenced literal block removed, as a renderer would treat it."""
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
    return "\n".join(kept)


@settings(max_examples=60, deadline=None)
@given(st.text(max_size=80))
def test_markdown_inline_stays_inert(value: str) -> None:
    shown = markdown_inline(value)

    assert "\n" not in shown
    assert "<" not in shown
    assert not re.search(r"(?<!\\)[\[\]()|`*_]", shown)


def test_rendering_is_deterministic_and_has_no_clock() -> None:
    built = document()

    assert render_report(built) == render_report(built)
    html, markdown = render_report(built)
    assert built.metadata.created_at in html
    assert r"2026\-01\-01T00\:00\:00\.000000Z" in markdown


def test_terminal_summary_lists_finding_command_and_fix() -> None:
    lines = terminal_lines(document(treatment=PlainTreatment()), shell="posix")  # noqa: S604
    text = "\n".join(lines)

    assert "Gate: 1 finding at a gated severity." in text
    assert "Reproduce: gazua run --tools --config gazua.yaml --mold idor-02" in text
    assert "Fix (fix-idor_via_agent)" in text
    assert "Conditions: fixture_specific." in text
