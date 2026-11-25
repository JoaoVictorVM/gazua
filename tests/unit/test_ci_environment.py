import json
import os
from pathlib import Path

import pytest
from ci_support import REPOSITORY, environment, event_file

from gazua.ci.environment import (
    CiError,
    event_context,
    parse_bool,
    parse_mold,
    target_environment,
    workspace_file,
)


def test_pull_request_target_is_refused_before_config(tmp_path: Path) -> None:
    values = environment(tmp_path, event="pull_request_target")
    values["GITHUB_EVENT_PATH"] = str(tmp_path / "never-read.json")

    with pytest.raises(CiError) as caught:
        event_context(values, "tools")

    assert caught.value.code == "ci_pull_request_target_refused"
    assert not (tmp_path / "never-read.json").exists()


@pytest.mark.parametrize("event", ["issue_comment", "pull_request_review", "workflow_run", ""])
def test_unsupported_events_are_refused(tmp_path: Path, event: str) -> None:
    with pytest.raises(CiError) as caught:
        event_context(environment(tmp_path, event=event), "tools")

    assert caught.value.code == "ci_event_refused"


def test_fork_forces_tools(tmp_path: Path) -> None:
    values = environment(tmp_path)
    event_file(tmp_path, head="attacker/repo")

    context = event_context(values, "agent")

    assert (context.fork, context.requested_mode, context.effective_mode) == (
        True,
        "agent",
        "tools",
    )
    assert context.forced_tools
    assert context.pull_request == 7


def test_same_repository_keeps_requested_mode(tmp_path: Path) -> None:
    context = event_context(environment(tmp_path), "agent")

    assert (context.fork, context.effective_mode) == (False, "agent")


@pytest.mark.parametrize(
    "change",
    [
        {"head": None},
        {"number": "7"},
        {"number": 0},
        {"head": "../../etc"},
    ],
)
def test_missing_fork_identity_is_not_trusted(tmp_path: Path, change: dict[str, object]) -> None:
    values = environment(tmp_path)
    event_file(tmp_path, **change)  # type: ignore[arg-type]

    with pytest.raises(CiError) as caught:
        event_context(values, "agent")

    assert caught.value.code == "ci_event_invalid"


def test_payload_must_match_repository(tmp_path: Path) -> None:
    values = environment(tmp_path)
    path = Path(values["GITHUB_EVENT_PATH"])
    data = json.loads(path.read_text(encoding="utf-8"))
    data["repository"]["full_name"] = "other/repo"
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(CiError):
        event_context(values, "tools")
    with pytest.raises(CiError):
        event_context({**values, "GITHUB_EVENT_PATH": ""}, "tools")
    path.write_text("[" * 100 + "]" * 100, encoding="utf-8")
    with pytest.raises(CiError):
        event_context(values, "tools")


def test_push_is_trusted_without_pull_request(tmp_path: Path) -> None:
    values = environment(tmp_path, event="push")

    context = event_context(values, "agent")

    assert (context.pull_request, context.effective_mode, context.repository) == (
        None,
        "agent",
        REPOSITORY,
    )


def test_token_is_removed_from_target_environment() -> None:
    values = {
        "PATH": "/bin",
        "GITHUB_TOKEN": "ghs_x",
        "GH_TOKEN": "ghs_y",
        "github_token": "lower",
        "GAZUA_CI_TOKEN": "ghs_z",
        "GAZUA_CI_MODE": "agent",
        "INPUT_GITHUB-TOKEN": "ghs_w",
        "ACTIONS_RUNTIME_TOKEN": "r",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "o",
        "OPENAI_API_KEY": "kept-for-agent-mode-in-trusted-context",
        "GITHUB_REPOSITORY": REPOSITORY,
    }

    cleaned = target_environment(values)

    assert cleaned == {
        "PATH": "/bin",
        "OPENAI_API_KEY": "kept-for-agent-mode-in-trusted-context",
        "GITHUB_REPOSITORY": REPOSITORY,
    }


def test_workspace_links_are_refused(tmp_path: Path) -> None:
    (tmp_path / "gazua.yaml").write_text("x", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "gazua.yaml").write_text("x", encoding="utf-8")
    outside = tmp_path.parent / f"{tmp_path.name}-outside.yaml"
    outside.write_text("x", encoding="utf-8")

    assert workspace_file(tmp_path, "gazua.yaml") == "gazua.yaml"
    assert workspace_file(tmp_path, "sub/gazua.yaml") == "sub/gazua.yaml"
    for text in ("../x.yaml", str(outside), "sub", "missing.yaml", "", "https://x/gazua.yaml"):
        with pytest.raises(CiError) as caught:
            workspace_file(tmp_path, text)
        assert caught.value.code == "ci_path_refused"
    try:
        os.symlink(outside, tmp_path / "link.yaml")
        os.symlink(tmp_path / "sub", tmp_path / "linked", target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links are not available")
    for text in ("link.yaml", "linked/gazua.yaml"):
        with pytest.raises(CiError):
            workspace_file(tmp_path, text)


def test_inputs_accept_only_their_values() -> None:
    assert parse_bool("true") is True
    assert parse_bool("false") is False
    assert parse_mold("idor-01") == "idor-01"
    assert parse_mold("") is None
    for text in ("True", "yes", "1", ""):
        with pytest.raises(CiError):
            parse_bool(text)
    for text in ("idor-01; rm -rf /", "$(id)", "-x", "a b"):
        with pytest.raises(CiError):
            parse_mold(text)
