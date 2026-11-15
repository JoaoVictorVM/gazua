import json
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest

from gazua.modes.agent_models import NOT_REPORTED_TEXT
from gazua.reports.rendering import render_report, terminal_lines
from gazua.reports.storage import RunLoadError, parse_run_document

EXAMPLE = Path(__file__).resolve().parents[1] / "support" / "run-example.json"


def test_old_run_documents_and_tools_are_unchanged(tools_project: Any) -> None:
    content = EXAMPLE.read_bytes()
    legacy = parse_run_document(content)
    assert legacy.legitimate_use is None
    assert legacy.engine.stop_reason is None
    html, markdown = render_report(legacy)
    assert "Legitimate use" not in html
    assert "Legitimate use" not in markdown
    assert not any("Legitimate use" in line for line in terminal_lines(legacy))

    # An agent document from before the measurement existed says so; it is never 100%.
    data = json.loads(content)
    data["metadata"]["mode"] = "agent"
    agent_legacy = parse_run_document(json.dumps(data).encode("utf-8"))
    assert NOT_REPORTED_TEXT in terminal_lines(agent_legacy)

    # Tools mode never carries legitimate use, and runs no task or stop policy.
    data = json.loads(content)
    data["legitimate_use"] = {
        "planned": 0,
        "evaluated": 0,
        "succeeded": 0,
        "failed": 0,
        "not_tested": 0,
        "rate": None,
        "coverage": "not_tested",
        "tasks": [],
    }
    with pytest.raises(RunLoadError):
        parse_run_document(json.dumps(data).encode("utf-8"))

    tools_project.write(legit_tasks=[{"request": "Show my order", "expected_tool": "get_order"}])
    result = tools_project.run(mold="idor-01")
    keys = {record.request_key for record in result.engine.records}
    assert not any(key.startswith("legitimate:") for key in keys)
    assert result.engine.stop_reason is None
    assert "entrypoint_called" not in {item["kind"] for item in tools_project.effects()}


IMPORT_TRAP = (
    "import json, os\n"
    "with open(os.path.join(os.path.dirname(__file__), 'imported.json'), 'w') as handle:\n"
    "    json.dump({'module': __name__}, handle)\n"
)
PLANTED = "ghp_" + "Qx7Lm2Rt9Wv4Yz8Kp3Nb6Hc1Jd5Fg0Sa2Ue7"


def agent_cli(agent_project: Any, *arguments: str, **extra: str) -> Any:
    from report_support import local_environment

    (agent_project.root / ".gitignore").write_text(".gazua/\n", encoding="utf-8")
    return agent_project.cli("--agent", *arguments, env=local_environment(**extra))


def test_agent_document_regenerates_legitimate_rate_offline(
    agent_project: Any, tmp_path: Path
) -> None:
    from report_support import local_environment

    from conftest import SPY, run_process

    first = agent_cli(agent_project, "--mold", "secret-04")
    assert first.returncode == 1, first.stderr
    latest = agent_project.root / ".gazua"
    original_markdown = (latest / "report.md").read_text(encoding="utf-8")
    original_html = (latest / "report.html").read_text(encoding="utf-8")
    stored = json.loads((latest / "run.json").read_text(encoding="utf-8"))
    assert stored["metadata"]["mode"] == "agent"
    assert stored["legitimate_use"]["rate"] == 1.0
    assert "Legitimate use: 1/1 tasks used the expected tool (100%)" in original_markdown
    assert stored["findings"][0]["reproduction"]["argv"][:3] == ["gazua", "run", "--agent"]

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    shutil.copy(latest / "run.json", elsewhere / "copied.json")
    shutil.rmtree(agent_project.root)
    (elsewhere / "agent_target.py").write_text(IMPORT_TRAP, encoding="utf-8")
    report = tmp_path / "spy.json"
    spied = run_process(
        [sys.executable, SPY, report, "cli", "report", "--from", "copied.json"],
        cwd=elsewhere,
        env=local_environment(),
    )

    assert spied.returncode == 0, spied.stderr
    observed = json.loads(report.read_text(encoding="utf-8"))
    assert observed["network"] == []
    assert observed["credential_reads"] == []
    assert not (elsewhere / "imported.json").exists()
    regenerated = elsewhere / ".gazua"
    assert (regenerated / "report.md").read_text(encoding="utf-8") == original_markdown
    assert (regenerated / "report.html").read_text(encoding="utf-8") == original_html


def test_agent_text_is_redacted_escaped_and_terminal_clean(agent_project: Any) -> None:
    agent_project.behave("leaky")

    result = agent_cli(agent_project, "--mold", "secret-04", GAZUA_TEST_PLANTED=PLANTED)

    assert result.returncode == 1, result.stderr
    latest = agent_project.root / ".gazua"
    html = (latest / "report.html").read_text(encoding="utf-8")
    markdown = (latest / "report.md").read_text(encoding="utf-8")
    stored = (latest / "run.json").read_text(encoding="utf-8")
    everything = "".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in sorted(latest.rglob("*"))
        if path.is_file()
    )
    for text in (result.stdout, result.stderr, everything):
        assert PLANTED not in text
    # The declared canary is synthetic test data and stays visible as the proof.
    assert "GAZUA-CANARY-7f3a9c" in stored
    assert "<script>alert(1)</script>" not in html
    assert "\x1b" not in result.stdout
    assert "\x1b" not in markdown
    assert "\x07" not in markdown
    assert "evil.example" not in result.stdout
