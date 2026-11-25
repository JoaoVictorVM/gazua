import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
ACTION = ROOT / "action.yml"
EXAMPLE = ROOT / "docs" / "examples" / "gazua-github-actions.yml"
INTERNAL = ROOT / ".github" / "workflows" / "gazua.yml"
PINNED = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
MINIMAL = {"contents": "read", "pull-requests": "write", "security-events": "write"}


def _load(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _events(document: dict[str, Any]) -> Any:
    # PyYAML reads the bare key `on` as the boolean true.
    return document.get("on", document.get(True))


def _steps(document: dict[str, Any]) -> list[dict[str, Any]]:
    if "runs" in document:
        return list(document["runs"]["steps"])
    return [step for job in document["jobs"].values() for step in job["steps"]]


def _action_steps() -> dict[str, dict[str, Any]]:
    return {step.get("id", step.get("name", "")): step for step in _steps(_load(ACTION))}


@pytest.mark.parametrize("path", [EXAMPLE, INTERNAL])
def test_example_uses_pull_request_only(path: Path) -> None:
    document = _load(path)

    assert set(_events(document)) == {"pull_request"}
    for text in (path, ACTION):
        assert "pull_request_target:" not in text.read_text(encoding="utf-8")


@pytest.mark.parametrize("path", [EXAMPLE, INTERNAL])
def test_permissions_are_minimal(path: Path) -> None:
    document = _load(path)
    jobs = document["jobs"].values()

    if path == EXAMPLE:
        assert document["permissions"] == MINIMAL
        assert all("permissions" not in job for job in jobs)
    else:
        # This repository grants writes per job; the top level stays read-only.
        assert document["permissions"] == {"contents": "read"}
        assert all(job["permissions"] == MINIMAL for job in jobs)
    assert "permissions" not in _load(ACTION)
    assert "${{ secrets." not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize("path", [ACTION, EXAMPLE, INTERNAL])
def test_all_actions_use_full_sha(path: Path) -> None:
    uses = [step["uses"] for step in _steps(_load(path)) if "uses" in step]

    assert uses
    for item in uses:
        assert item == "./" or PINNED.fullmatch(item), item


@pytest.mark.parametrize("path", [EXAMPLE, INTERNAL])
def test_checkout_does_not_persist_credentials(path: Path) -> None:
    checkouts = [
        step
        for step in _steps(_load(path))
        if str(step.get("uses", "")).startswith("actions/checkout@")
    ]

    assert checkouts
    assert all(step["with"]["persist-credentials"] is False for step in checkouts)


def test_evidence_upload_is_opt_in() -> None:
    document = _load(ACTION)
    steps = _action_steps()
    uploads = [
        step
        for step in steps.values()
        if str(step.get("uses", "")).startswith("actions/upload-artifact@")
    ]

    assert document["inputs"]["upload-evidence"]["default"] == "false"
    [evidence] = uploads
    assert "inputs.upload-evidence == 'true'" in evidence["if"]
    assert evidence["with"]["path"] == "${{ steps.run.outputs.evidence }}"
    assert evidence["with"]["include-hidden-files"] is False
    assert evidence["with"]["retention-days"] == 7
    assert "*" not in evidence["with"]["path"]


def test_token_reaches_only_the_comment_step() -> None:
    steps = _action_steps()

    holders = [
        name
        for name, step in steps.items()
        if "inputs.github-token" in str(step.get("env", {})) + str(step.get("run", ""))
    ]
    assert holders == ["comment"]
    assert "GAZUA_CI_TOKEN" in steps["comment"]["env"]
    assert steps["run"]["env"]["GAZUA_CI_CONTRACT"] == "1"


def test_inputs_never_reach_shell_text() -> None:
    for step in _steps(_load(ACTION)):
        script = str(step.get("run", ""))
        assert "${{" not in script, step.get("name")


def test_sarif_and_auxiliary_steps_never_decide_the_gate() -> None:
    steps = _action_steps()

    assert steps["sarif"]["continue-on-error"] is True
    assert steps["evidence"]["continue-on-error"] is True
    assert steps["comment"]["continue-on-error"] is True
    assert str(steps["sarif"]["uses"]).startswith("github/codeql-action/upload-sarif@")
    assert steps["sarif"]["with"]["category"] == "${{ steps.run.outputs.sarif-category }}"
    assert "GAZUA_CI_SARIF_OUTCOME" in steps["finish"]["env"]
    assert "GAZUA_CI_EVIDENCE_OUTCOME" in steps["finish"]["env"]
    setup = next(step for step in steps.values() if "setup-uv" in str(step.get("uses", "")))
    assert setup["with"]["enable-cache"] is False
