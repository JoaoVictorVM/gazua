import json
from typing import Any

from action_support import action_environment, run_action
from ci_support import API, FakeGitHub

from gazua.ci.action import comment_step
from gazua.reports.storage import load_run_document


def _publish(root: Any, fake: FakeGitHub, path: str) -> str:
    values = action_environment(
        root, GAZUA_CI_TOKEN="ghs_" + "t" * 36, GAZUA_CI_COMMENT_PATH=path, GITHUB_API_URL=API
    )
    return comment_step(values, fake)


def test_second_run_updates_one_comment(tools_project: Any) -> None:
    fake = FakeGitHub()
    fake.add("Looks good to me", login="reviewer")

    _, first = run_action(tools_project.root, GAZUA_CI_MOLD="idor-01")
    created = _publish(tools_project.root, fake, first.values["comment"])
    _, second = run_action(tools_project.root, GAZUA_CI_MOLD="idor-01")
    updated = _publish(tools_project.root, fake, second.values["comment"])
    again = _publish(tools_project.root, fake, second.values["comment"])

    assert (created, updated, again) == ("created", "updated", "unchanged")
    assert len(fake.owned()) == 1
    assert len(fake.comments) == 2
    body = fake.owned()[0]["body"]
    run = load_run_document(tools_project.root / ".gazua" / "run.json")
    assert run.run_id in body


def test_comment_contains_summary_and_local_reproduction(tools_project: Any) -> None:
    _, outputs = run_action(tools_project.root, GAZUA_CI_MOLD="idor-01")

    body = (tools_project.root / outputs.values["comment"]).read_text(encoding="utf-8")

    run = load_run_document(tools_project.root / ".gazua" / "run.json")
    [finding] = run.findings
    assert "**1 new high finding, 0 known, 0 not tested**" in body
    assert f"`{finding.id}`" in body
    assert "`gazua run --tools --config gazua.yaml --mold idor-01`" in body
    assert "`.gazua/report.html`" in body


def test_comment_contains_no_attack_or_conversation(tools_project: Any) -> None:
    _, outputs = run_action(tools_project.root)

    body = (tools_project.root / outputs.values["comment"]).read_text(encoding="utf-8")
    data = (tools_project.root / ".gazua/ci/comment.json").read_text(encoding="utf-8")

    run = load_run_document(tools_project.root / ".gazua" / "run.json")
    assert run.findings
    for text in (body, data):
        for scenario in run.scenarios:
            assert scenario.attack not in text
            assert json.dumps(scenario.payload) not in text
        for proof in run.proofs:
            assert proof.execution_id not in text
        assert "GAZUA-CANARY-7f3a9c" not in text
        assert "order-victim-1" not in text
        assert str(tools_project.root) not in text


def test_api_pagination_does_not_duplicate(tools_project: Any) -> None:
    fake = FakeGitHub()
    for index in range(250):
        fake.add(f"discussion {index}", login="someone")
    _, outputs = run_action(tools_project.root, GAZUA_CI_MOLD="idor-01")
    body = (tools_project.root / outputs.values["comment"]).read_text(encoding="utf-8")
    fake.add(body.replace("1 new high finding", "stale"))

    status = _publish(tools_project.root, fake, outputs.values["comment"])

    assert status == "updated"
    assert len(fake.owned()) == 1
    pages = [item.url for item in fake.requests if item.method == "GET" and "comments" in item.url]
    assert len(pages) == 3
