from pathlib import Path
from typing import Any

from action_support import Spy, action_environment, run_action
from ci_support import API, FakeGitHub, event_file

from gazua.ci.action import comment_step, finish_step


def test_fork_agent_request_runs_tools_only(tools_project: Any, capsys: Any) -> None:
    event_file(tools_project.root, head="attacker/repo")
    spy = Spy()

    outcome, outputs = run_action(tools_project.root, spy, GAZUA_CI_MODE="agent")

    [(argv, cwd, _)] = spy.calls
    assert argv[3:5] == ["run", "--tools"]
    assert "--agent" not in argv
    assert cwd == tools_project.root.resolve()
    assert outputs.values["effective-mode"] == "tools"
    assert outcome.effective_mode == "tools"
    assert "only tools mode runs" in capsys.readouterr().out


def test_fork_target_receives_no_github_token(tools_project: Any) -> None:
    event_file(tools_project.root, head="attacker/repo")
    spy = Spy()

    run_action(
        tools_project.root,
        spy,
        GITHUB_TOKEN="ghs_" + "a" * 36,
        GH_TOKEN="ghs_" + "b" * 36,
        GAZUA_CI_TOKEN="ghs_" + "c" * 36,
        ACTIONS_RUNTIME_TOKEN="runtime",  # noqa: S106
    )

    [(_, _, env)] = spy.calls
    names = {name.upper() for name in env}
    assert not names & {"GITHUB_TOKEN", "GH_TOKEN", "GAZUA_CI_TOKEN", "ACTIONS_RUNTIME_TOKEN"}
    assert not any(name.startswith(("GAZUA_CI_", "INPUT_")) for name in names)
    assert not any(value.startswith("ghs_") for value in env.values())


def test_pull_request_target_executes_no_project_code(tools_project: Any) -> None:
    spy = Spy()

    outcome, outputs = run_action(tools_project.root, spy, GITHUB_EVENT_NAME="pull_request_target")

    assert spy.calls == []
    assert outcome.exit_code == 2
    assert outcome.codes == ["ci_pull_request_target_refused"]
    assert outputs.values == {"exit-code": "2"}
    assert not (tools_project.root / ".gazua").exists()
    assert not (tools_project.root / "effects").exists()


def test_fork_without_comment_permission_keeps_summary(tools_project: Any) -> None:
    event_file(tools_project.root, head="attacker/repo")
    outcome, outputs = run_action(tools_project.root, GAZUA_CI_MOLD="idor-01")
    fake = FakeGitHub(status={"POST": 403})
    values = action_environment(
        tools_project.root,
        GAZUA_CI_TOKEN="ghs_" + "r" * 36,
        GAZUA_CI_COMMENT_PATH=outputs.values["comment"],
        GITHUB_API_URL=API,
    )

    status = comment_step(values, fake)

    assert status == "ci_comment_permission"
    assert fake.owned() == []
    summary = Path(values["GITHUB_STEP_SUMMARY"]).read_text(encoding="utf-8")
    assert "**1 new high finding" in summary
    assert "lacks permission" in summary
    assert finish_step({"GAZUA_CI_EXIT_CODE": outputs.values["exit-code"]}) == 1
    assert outcome.exit_code == 1
