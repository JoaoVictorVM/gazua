import json
from pathlib import Path
from typing import Any

from report_factory import document
from verify_support import gazua, latest_run

from gazua.reports.storage import document_json


def _issues(root: Path, run_id: str) -> list[Path]:
    return sorted((root / ".gazua" / "issues" / run_id).glob("*.md"))


def test_one_file_per_finding(tools_project: Any) -> None:
    ran = tools_project.cli("--tools")
    assert ran.returncode == 1, ran.stdout + ran.stderr
    run = latest_run(tools_project.root)
    assert len(run["findings"]) >= 2

    exported = gazua(tools_project.root, "issues")

    assert exported.returncode == 0, exported.stdout + exported.stderr
    files = _issues(tools_project.root, run["run_id"])
    assert [path.name for path in files] == sorted(f"{item['id']}.md" for item in run["findings"])
    for path in files:
        content = path.read_text(encoding="utf-8")
        finding_id = path.name.removesuffix(".md")
        assert finding_id.replace("-", "\\-") in content
        assert "## Acceptance criteria" in content
        assert "- [ ] " in content
        assert f"gazua verify {finding_id} --mode tools" in content
    folder = f".gazua/issues/{run['run_id']}/"
    assert f"Wrote {len(files)} issue files to {folder}" in exported.stdout
    assert "never opens issues" in exported.stdout
    again = gazua(tools_project.root, "issues")
    assert again.returncode == 0
    assert "already up to date" in again.stdout


def test_known_and_ungated_findings_are_exported(tools_project: Any) -> None:
    tools_project.write(gate={"fail_on": []})
    ran = tools_project.cli("--tools", "--mold", "idor-01")
    assert ran.returncode == 0, ran.stdout + ran.stderr
    assert gazua(tools_project.root, "baseline").returncode == 0
    known = tools_project.cli("--tools", "--mold", "idor-01")
    assert known.returncode == 0
    run = latest_run(tools_project.root)
    [finding] = run["findings"]
    assert finding["gated"] is False
    assert run["baseline"]["entries"][0]["status"] == "open"

    exported = gazua(tools_project.root, "issues")

    assert exported.returncode == 0, exported.stderr
    [path] = _issues(tools_project.root, run["run_id"])
    content = path.read_text(encoding="utf-8")
    assert "not gated" in content
    assert "Baseline: known\\, accepted as open" in content


def test_nonfinding_states_do_not_export(tmp_path: Path) -> None:
    built = document()
    (tmp_path / "run.json").write_text(document_json(built), encoding="utf-8")

    exported = gazua(tmp_path, "issues", "--from", "run.json")

    assert exported.returncode == 0, exported.stderr
    files = _issues(tmp_path, built.run_id)
    assert [path.name for path in files] == [f"{built.findings[0].id}.md"]
    states = {item.state for item in built.verdicts.results}
    assert {"resisted", "not_tested", "not_applicable", "conditional_risk"} <= states
    content = files[0].read_text(encoding="utf-8")
    for scenario in built.scenarios:
        if scenario.attack_key not in built.findings[0].scenarios:
            assert scenario.attack_key.replace(":", "\\:").replace("-", "\\-") not in content


def test_zero_findings_returns_zero(tools_project: Any) -> None:
    tools_project.harden()
    ran = tools_project.cli("--tools", "--mold", "idor-01")
    assert ran.returncode == 0, ran.stdout + ran.stderr
    run = latest_run(tools_project.root)
    assert run["findings"] == []

    exported = gazua(tools_project.root, "issues")

    assert exported.returncode == 0, exported.stderr
    assert "0 issue files written" in exported.stdout
    assert not (tools_project.root / ".gazua" / "issues").exists()


def test_corrupt_or_unknown_run_returns_two(tmp_path: Path) -> None:
    missing = gazua(tmp_path, "issues")
    assert missing.returncode == 2
    assert "No run.json at this path." in missing.stderr

    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    corrupt = gazua(tmp_path, "issues", "--from", "bad.json")
    assert corrupt.returncode == 2
    assert "not valid JSON" in corrupt.stderr

    data = json.loads(document_json(document()))
    data["schema_version"] = 99
    (tmp_path / "future.json").write_text(json.dumps(data), encoding="utf-8")
    future = gazua(tmp_path, "issues", "--from", "future.json")
    assert future.returncode == 2
    assert "schema version" in future.stderr

    url = gazua(tmp_path, "issues", "--from", "https://example.org/run.json")
    assert url.returncode == 2
    assert not (tmp_path / ".gazua" / "issues").exists()


def test_export_does_not_inherit_run_failure(tools_project: Any) -> None:
    ran = tools_project.cli("--tools", "--mold", "idor-01")
    assert ran.returncode == 1
    run = latest_run(tools_project.root)
    assert run["report_exit_code"] == 1
    assert run["findings"][0]["gated"] is True

    exported = gazua(tools_project.root, "issues")

    assert exported.returncode == 0, exported.stderr
    assert len(_issues(tools_project.root, run["run_id"])) == 1
