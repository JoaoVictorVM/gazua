import json
import shutil
import sys
from pathlib import Path
from typing import Any

from report_support import echo_project, gazua, local_environment, read_json

from conftest import SPY, run_process

IMPORT_TRAP = (
    "import json, os\n"
    "with open(os.path.join(os.path.dirname(__file__), 'imported.json'), 'w') as handle:\n"
    "    json.dump({'module': __name__}, handle)\n"
)


def test_regenerates_equivalent_reports_from_only_json(tmp_path: Path) -> None:
    project = echo_project(tmp_path / "project")
    first = gazua(project, "run", "--tools", "--mold", "idor-01")
    assert first.returncode == 1, first.stderr
    latest = project / ".gazua"
    original_html = (latest / "report.html").read_text(encoding="utf-8")
    original_markdown = (latest / "report.md").read_text(encoding="utf-8")
    original = read_json(latest / "run.json")

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    shutil.copy(latest / "run.json", elsewhere / "copied.json")
    shutil.rmtree(project)
    (elsewhere / "echo_target.py").write_text(IMPORT_TRAP, encoding="utf-8")
    report = tmp_path / "spy.json"

    spied = run_process(
        [sys.executable, SPY, report, "cli", "report", "--from", "copied.json"],
        cwd=elsewhere,
        env=local_environment(),
    )

    assert spied.returncode == 0, spied.stderr
    observed = json.loads(report.read_text(encoding="utf-8"))
    assert observed["exit_code"] == 0
    assert observed["network"] == []
    assert observed["credential_reads"] == []
    assert observed["environment_listed"] is False
    assert not (elsewhere / "imported.json").exists()
    assert not any("gazua.yaml" in path for path in observed["opened_paths"])
    regenerated = elsewhere / ".gazua"
    assert (regenerated / "report.html").read_text(encoding="utf-8") == original_html
    assert (regenerated / "report.md").read_text(encoding="utf-8") == original_markdown
    assert read_json(regenerated / "run.json") == original
    assert not (regenerated / "runs").exists()
    assert original["run_id"] in spied.stdout

    again = gazua(elsewhere, "report", "--from", str(regenerated / "run.json"))
    assert again.returncode == 0, again.stderr
    assert read_json(regenerated / "run.json") == original


def _write(path: Path, data: Any) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_invalid_sources_exit_two_without_writing(tmp_path: Path) -> None:
    project = echo_project(tmp_path / "project")
    assert gazua(project, "run", "--tools", "--mold", "idor-01").returncode == 1
    valid = read_json(project / ".gazua" / "run.json")
    work = tmp_path / "work"
    work.mkdir()
    deep: Any = 1
    for _ in range(70):
        deep = [deep]
    cases = {
        "missing.json": "No run.json at this path.",
        _write(work / "future.json", {**valid, "schema_version": 2}).name: "migration",
        _write(work / "broken.json", {**valid, "findings": "x"}).name: "run schema",
        _write(work / "deep.json", {**valid, "payload": deep}).name: "64 levels",
    }
    (work / "text.json").write_text("{not json", encoding="utf-8")
    cases["text.json"] = "not valid JSON"

    for name, message in cases.items():
        result = gazua(work, "report", "--from", name)
        assert result.returncode == 2, name
        assert message in result.stderr, (name, result.stderr)
    url = gazua(work, "report", "--from", "https://example.com/run.json")
    assert url.returncode == 2
    assert "not a URL" in url.stderr
    assert not (work / ".gazua" / "report.html").exists()
