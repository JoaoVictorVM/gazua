import json
import sys
from typing import Any

from conftest import run_process


def gazua(project: Any, *arguments: str) -> Any:
    return run_process([sys.executable, "-m", "gazua", *arguments], cwd=project.root)


def read(project: Any, name: str) -> str:
    return (project.root / ".gazua" / name).read_text(encoding="utf-8")


def test_regeneration_uses_snapshot_after_baseline_changes(tools_project: Any) -> None:
    tools_project.cli("--tools", "--mold", "idor-01")
    gazua(tools_project, "baseline")
    compared = tools_project.cli("--tools", "--mold", "idor-01")
    assert compared.returncode == 0
    run = json.loads(read(tools_project, "run.json"))
    archive = f".gazua/runs/{run['run_id']}/run.json"
    snapshot = run["baseline"]
    (tools_project.root / "gazua-baseline.json").unlink()
    (tools_project.root / "tools_target.py").unlink()
    tools_project.clear_effects()

    rebuilt = gazua(tools_project, "report", "--from", archive)

    assert rebuilt.returncode == 0, rebuilt.stderr
    assert "1 known finding, 0 new" in rebuilt.stdout
    assert json.loads(read(tools_project, "run.json"))["baseline"] == snapshot
    for name in ("report.md", "report.html"):
        text = read(tools_project, name).replace("\\", "")
        assert "Baseline comparison" in text
        assert "1 known finding, 0 new" in text
        assert run["findings"][0]["id"] in text
    assert tools_project.effects() == []


def test_known_findings_keep_proofs_and_native_rates(tools_project: Any) -> None:
    tools_project.cli("--tools", "--mold", "idor-01")
    before = json.loads(read(tools_project, "run.json"))
    gazua(tools_project, "baseline")

    tools_project.cli("--tools", "--mold", "idor-01")

    after = json.loads(read(tools_project, "run.json"))
    assert after["findings"][0]["id"] == before["findings"][0]["id"]
    assert len(after["proofs"]) == len(before["proofs"])
    assert after["findings"][0]["gated"] is True

    def native(document: dict[str, Any]) -> list[tuple[Any, ...]]:
        return [
            (item["attack_key"], item["state"], item["rate"], item["upper_bound"], item["gated"])
            for item in document["verdicts"]["results"]
        ]

    assert native(after) == native(before)
    markdown = read(tools_project, "report.md")
    assert "Proof proof-000001" in markdown
    assert "accepted" in markdown
