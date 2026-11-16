import json
import re
import shutil
from pathlib import Path
from typing import Any

from report_factory import document
from report_support import echo_project, gazua, read_json
from verify_support import latest_run

from gazua.reports.fixes import guide_for
from gazua.reports.rendering import build_view, render_report

ROOT = Path(__file__).resolve().parents[2]
IMPORT_TRAP = (
    "import json, os\n"
    "with open(os.path.join(os.path.dirname(__file__), 'imported.json'), 'w') as handle:\n"
    "    json.dump({'module': __name__}, handle)\n"
)


def _articles(html: str) -> dict[str, str]:
    pattern = r'<article class="finding[^"]*" id="(finding-[0-9a-f]{64})">(.*?)</article>'
    return dict(re.findall(pattern, html, re.S))


def test_each_finding_links_to_correct_guide(tools_project: Any) -> None:
    ran = tools_project.cli("--tools")
    assert ran.returncode == 1, ran.stdout + ran.stderr
    run = latest_run(tools_project.root)
    html = (tools_project.root / ".gazua" / "report.html").read_text(encoding="utf-8")
    markdown = (tools_project.root / ".gazua" / "report.md").read_text(encoding="utf-8")
    articles = _articles(html)
    guide = guide_for("en")

    assert run["guide"]["origin"] == "captured"
    assert len(run["findings"]) >= 2
    for finding in run["findings"]:
        damage = finding["damage"]
        block = articles[finding["id"]]
        assert f'href="#fix-{damage}"' in block
        assert re.findall(r'href="#fix-([a-z_]+)"', block) == [damage]
        assert f"{finding['id']}.md" in block
        assert f"gazua verify {finding['id']} --mode tools" in block
        assert f"](#fix-{damage})" in markdown
        target = html.split(f'<article class="guide" id="fix-{damage}">')[1].split("</article>")[0]
        assert guide.entry(damage).fixes_cause[0].replace("'", "&#39;") in target
    for damage in guide.entries:
        assert f'<article class="guide" id="fix-{damage}">' in html
        assert f'<a id="fix-{damage}"></a>' in markdown
    assert "Confirm the fix" in ran.stdout


def test_low_group_keeps_individual_guide_and_issue_reference() -> None:
    built = document()
    [finding] = built.findings
    lows = [
        finding.model_copy(update={"id": f"finding-{str(number) * 64}", "severity": "low"})
        for number in (1, 2)
    ]
    grouped = built.model_copy(update={"findings": lows})
    view = build_view(grouped)
    assert any(getattr(entry, "findings", None) for entry in view.groups)

    html, markdown = render_report(grouped)

    group = html.split('<details class="low-group"')[1].split("</details>")[0]
    for low in lows:
        block = _articles(group)[low.id]
        assert 'href="#fix-idor_via_agent"' in block
        assert f"{low.id}.md" in block
        assert f"gazua verify {low.id} --mode tools" in block
        section = markdown.split(f'<a id="{low.id}"></a>')[1].split("<a id=")[0]
        assert "](#fix-idor_via_agent)" in section
        assert f"gazua verify {low.id} --mode tools" in section


def test_regeneration_uses_snapshot_without_target(tmp_path: Path) -> None:
    project = echo_project(tmp_path / "project")
    assert gazua(project, "run", "--tools", "--mold", "idor-01").returncode == 1
    data = read_json(project / ".gazua" / "run.json")
    data["guide"]["revision"] = 5
    data["guide"]["entries"]["idor_via_agent"]["fixes_cause"] = ["Snapshot only guidance."]
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "copied.json").write_text(json.dumps(data), encoding="utf-8")
    shutil.rmtree(project)
    (elsewhere / "echo_target.py").write_text(IMPORT_TRAP, encoding="utf-8")

    rebuilt = gazua(elsewhere, "report", "--from", "copied.json")

    assert rebuilt.returncode == 0, rebuilt.stderr
    assert not (elsewhere / "imported.json").exists()
    html = (elsewhere / ".gazua" / "report.html").read_text(encoding="utf-8")
    assert "Snapshot only guidance." in html
    assert guide_for("en").entry("idor_via_agent").fixes_cause[0] not in html
    assert "revision 5" in html
    assert "added when this document was read" not in html

    legacy = ROOT / "tests" / "support" / "run-example.json"
    shutil.copy(legacy, elsewhere / "legacy.json")
    old = gazua(elsewhere, "report", "--from", "legacy.json")
    assert old.returncode == 0, old.stderr
    shown = (elsewhere / ".gazua" / "report.md").read_text(encoding="utf-8")
    assert "added when this document was read" in shown
    assert (elsewhere / "legacy.json").read_bytes() == legacy.read_bytes()
    assert (elsewhere / ".gazua" / "run.json").read_bytes() == legacy.read_bytes()
