"""Reports of the demo: working reproduction, a notice that survives regeneration, inert data."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from demo_support import copy_workspace

from gazua.demo import SIMULATION_NOTICE
from gazua.reports.rendering import render_report, terminal_lines
from gazua.reports.storage import parse_run_document

SUPPORT = Path(__file__).resolve().parents[1] / "support"


def _gazua(
    workspace: Path, env: dict[str, str], *arguments: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "gazua", *arguments],
        cwd=workspace,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
        check=False,
    )


def test_each_finding_reproduction_runs(
    clean_demo: Any, tmp_path: Path, clean_environment: Any
) -> None:
    workspace = copy_workspace(clean_demo.workspace, tmp_path / "gazua-demo")
    commands: dict[tuple[str, ...], tuple[str, bool]] = {}
    for document in clean_demo.documents().values():
        for finding in document["findings"]:
            reproduction = finding["reproduction"]
            assert reproduction["available"] is True
            assert reproduction["cwd"] == "."
            argv = tuple(reproduction["argv"])
            gated = finding["gated"] or commands.get(argv, ("", False))[1]
            commands[argv] = (finding["mold_id"], gated)

    assert len(commands) >= 20
    for argv, (mold_id, gated) in commands.items():
        assert argv[:2] == ("gazua", "run")
        assert argv[argv.index("--config") + 1] == "gazua.yaml"
        result = _gazua(workspace, clean_environment(), *argv[1:])
        assert result.returncode == (1 if gated else 0), (argv, result.stderr)
        latest = json.loads((workspace / ".gazua" / "run.json").read_text(encoding="utf-8"))
        assert latest["metadata"]["demo"] is False
        assert [item["mold_id"] for item in latest["findings"]] == [mold_id] * len(
            latest["findings"]
        )
        assert latest["findings"]


def test_simulation_notice_survives_regeneration(
    clean_demo: Any, tmp_path: Path, clean_environment: Any
) -> None:
    notice = SIMULATION_NOTICE["en"]
    for document in clean_demo.documents().values():
        assert document["metadata"]["demo"] is True
        folder = clean_demo.workspace / ".gazua" / "runs" / document["run_id"]
        assert notice in (folder / "report.html").read_text(encoding="utf-8")
        assert notice in (folder / "report.md").read_text(encoding="utf-8").replace("\\", "")
    workspace = copy_workspace(clean_demo.workspace, tmp_path / "gazua-demo")
    agent = clean_demo.documents()["agent"]
    source = f".gazua/runs/{agent['run_id']}/run.json"
    (workspace / ".gazua" / "report.html").unlink()

    result = _gazua(workspace, clean_environment(), "report", "--from", source)

    assert result.returncode == 0, result.stderr
    assert notice in result.stdout
    assert notice in (workspace / ".gazua" / "report.html").read_text(encoding="utf-8")
    markdown = (workspace / ".gazua" / "report.md").read_text(encoding="utf-8")
    assert notice in markdown.replace("\\", "")


def test_legacy_report_defaults_demo_false() -> None:
    content = (SUPPORT / "run-example.json").read_bytes()
    assert b'"demo"' not in content

    document = parse_run_document(content)
    html, markdown = render_report(document)

    assert document.metadata.demo is False
    for notice in SIMULATION_NOTICE.values():
        assert notice not in html
        assert notice not in markdown
        assert notice not in terminal_lines(document)


def _outside_fences(markdown: str) -> str:
    """The Markdown lines that are not inside a fenced literal block."""
    kept: list[str] = []
    fence: str | None = None
    for line in markdown.splitlines():
        stripped = line.strip()
        if fence is None and stripped.startswith("```"):
            fence = stripped[: len(stripped) - len(stripped.lstrip("`"))]
        elif fence is not None and stripped == fence:
            fence = None
        elif fence is None:
            kept.append(line)
    return "\n".join(kept)


def test_report_payload_remains_inert(clean_demo: Any) -> None:
    agent = clean_demo.documents()["agent"]
    folder = clean_demo.workspace / ".gazua" / "runs" / agent["run_id"]
    html = (folder / "report.html").read_text(encoding="utf-8")
    markdown = (folder / "report.md").read_text(encoding="utf-8")

    assert "default-src 'none'" in html.replace("&#39;", "'")
    assert "gazuaMarker" in html
    # Markdown shows attack text only inside fenced literal blocks, where it is never rendered.
    outside_fences = _outside_fences(markdown)
    for raw in ('<img src=x onerror="gazuaMarker()">', "<script>gazuaMarker()</script>"):
        assert raw not in html
        assert raw not in outside_fences
    assert "&lt;script&gt;gazuaMarker()&lt;/script&gt;" in html
