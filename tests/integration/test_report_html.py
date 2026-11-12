import re
from html.parser import HTMLParser
from pathlib import Path

from report_support import echo_project, gazua, local_environment

PAYLOADS = [
    "<script>window.gazuaPwned=1</script>",
    '"><img src=x onerror="window.gazuaPwned=2">',
    "<svg/onload=window.gazuaPwned=3>",
    "</pre></article></main><script>fetch('https://evil.example/x')</script>",
    '<a href="javascript:window.gazuaPwned=4">click</a>',
    "<iframe src=https://evil.example></iframe>",
    "<base href=https://evil.example/>",
    "<meta http-equiv=refresh content='0;url=https://evil.example'>",
]


class Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))


def test_xss_does_not_execute_offline(tmp_path: Path) -> None:
    """Checks the HTML that a browser would parse; no browser is driven in this suite."""
    project = echo_project(tmp_path / "project")
    environment = local_environment(GAZUA_TEST_ECHO=" ".join(PAYLOADS))

    result = gazua(project, "run", "--tools", "--mold", "idor-01", env=environment)

    assert result.returncode == 1, result.stderr
    html = (project / ".gazua" / "report.html").read_text(encoding="utf-8")
    parser = Collector()
    parser.feed(html)
    tags = [tag for tag, _ in parser.tags]
    assert tags.count("script") == 1
    assert tags.count("style") == 1
    assert not {"img", "svg", "iframe", "base"} & set(tags)
    assert [attrs.get("http-equiv") for tag, attrs in parser.tags if tag == "meta"].count(
        "refresh"
    ) == 0
    assert not any(name.lower().startswith("on") for _, attrs in parser.tags for name in attrs)
    for tag, attrs in parser.tags:
        for name in ("href", "src", "action"):
            value = attrs.get(name)
            assert value is None or value.startswith("#"), (tag, value)
    assert "window.gazuaPwned" in html
    assert "&lt;script&gt;window.gazuaPwned=1&lt;/script&gt;" in html
    policy = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', html)
    assert policy is not None
    assert "connect-src &#39;none&#39;" in policy.group(1)
    assert "default-src &#39;none&#39;" in policy.group(1)
    assert "https://" not in html.split("<script>")[1]
    assert 'id="filter-damage"' in html
    assert 'id="filter-state"' in html
    assert 'data-damage="idor_via_agent"' in html
