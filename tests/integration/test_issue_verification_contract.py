import json
import re
import shlex
from pathlib import Path
from typing import Any

from verify_support import accepted, baseline_document, gazua, latest_run

from gazua.reports.storage import parse_run_document


def _issue(root: Path) -> tuple[str, str]:
    run = latest_run(root)
    exported = gazua(root, "issues")
    assert exported.returncode == 0, exported.stderr
    [path] = sorted((root / ".gazua" / "issues" / run["run_id"]).glob("*.md"))
    return path.name.removesuffix(".md"), path.read_text(encoding="utf-8")


def _verify_argv(content: str) -> list[str]:
    block = content.split("## Confirm the fix")[1].split("POSIX shell:")[1]
    [command] = re.findall(r"^gazua verify .*$", block, flags=re.MULTILINE)[:1]
    return shlex.split(command)


def test_issue_command_resolves_full_finding_id(tools_project: Any) -> None:
    root = tools_project.root
    entry = accepted(root, "--tools", "--mold", "idor-01")
    finding_id, content = _issue(root)
    argv = _verify_argv(content)
    assert argv == ["gazua", "verify", finding_id, "--mode", "tools"]
    assert entry["id"] == finding_id
    tools_project.harden()
    tools_project.clear_effects()

    verified = gazua(root, *argv[1:])

    assert verified.returncode == 0, verified.stdout + verified.stderr
    assert "0/20, up to ~14%: closed" in verified.stdout
    [closed] = baseline_document(root)["entries"]
    assert closed["status"] == "closed"

    data = latest_run(root)
    assert data["verification"] is not None
    data.pop("guide")
    data.pop("target_adapter")
    data.pop("mcp")
    data.pop("http")
    data.pop("typescript")
    data["schema_version"] = 2
    adapted = parse_run_document(json.dumps(data).encode())
    assert adapted.guide.origin == "legacy_fallback"
    assert adapted.model_dump(mode="json")["verification"] == data["verification"]
    assert adapted.model_dump(mode="json")["baseline"] == data["baseline"]


def test_missing_baseline_is_explained_not_created(tools_project: Any) -> None:
    root = tools_project.root
    assert tools_project.cli("--tools", "--mold", "idor-01").returncode == 1
    _, content = _issue(root)

    assert "gazua baseline" in content
    assert "Exporting this issue runs nothing and accepts nothing" in content
    assert not (root / "gazua-baseline.json").exists()

    attempted = gazua(root, *_verify_argv(content)[1:])

    assert attempted.returncode == 2
    assert not (root / "gazua-baseline.json").exists()


def test_zero_of_five_does_not_satisfy_issue_acceptance(agent_project: Any) -> None:
    root = agent_project.root
    accepted(root, "--agent", "--mold", "secret-04")
    _, content = _issue(root)
    agent_project.behave("hardened")

    normal = gazua(root, "run", "--agent", "--mold", "secret-04")

    assert normal.returncode == 0, normal.stdout + normal.stderr
    run = latest_run(root)
    [result] = [item for item in run["verdicts"]["results"] if item["mold_id"] == "secret-04"]
    assert (result["successes"], result["evaluated"]) == (0, 5)
    assert baseline_document(root)["entries"][0]["status"] == "open"
    criteria = content.split("## Acceptance criteria")[1]
    assert "20 conclusive repetitions" in criteria
    assert "0/5 does not close the finding" in criteria
    assert "--mode agent" in content
