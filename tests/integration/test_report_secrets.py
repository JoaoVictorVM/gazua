from pathlib import Path

from report_support import echo_project, every_file, gazua, local_environment, read_json

CANARY = "GAZUA-CANARY-7f3a9c"
PLANTED = "ghp_" + "Qx7Lm2Rt9Wv4Yz8Kp3Nb6Hc1Jd5Fg0Sa2Ue7"


def test_environment_secret_never_reaches_outputs(tmp_path: Path) -> None:
    project = echo_project(tmp_path / "project")
    environment = local_environment(GAZUA_TEST_ECHO=PLANTED)

    result = gazua(project, "run", "--tools", "--mold", "idor-01", env=environment)

    assert result.returncode == 1, result.stderr
    assert PLANTED not in result.stdout
    assert PLANTED not in result.stderr
    stored = every_file(project / ".gazua")
    assert PLANTED not in stored
    assert "[redacted-secret]" in stored
    engine = project / ".gazua" / "runs"
    assert any(path.name.endswith(".redacted.txt") for path in engine.rglob("*"))
    assert not any((engine).rglob("private"))


def test_declared_fixture_and_canary_stay_visible(tmp_path: Path) -> None:
    project = echo_project(tmp_path / "project")
    environment = local_environment(GAZUA_TEST_ECHO=f"{PLANTED} for maria@example.com")

    result = gazua(project, "run", "--tools", "--mold", "idor-01", env=environment)

    assert result.returncode == 1, result.stderr
    run = read_json(project / ".gazua" / "run.json")
    content = run["proofs"][0]["content"]["original"]
    assert content["canary"] == CANARY
    assert content["user_id"] == "victim-1"
    assert content["order_id"] == "order-victim-1"
    assert PLANTED not in content["note"]
    assert "maria@example.com" not in content["note"]
    assert run["synthetic_data"]["canaries"] == [CANARY]
    assert {item["id"] for item in run["synthetic_data"]["identities"]} == {
        "attacker-1",
        "victim-1",
    }
    html = (project / ".gazua" / "report.html").read_text(encoding="utf-8")
    assert CANARY in html
    assert PLANTED not in every_file(project / ".gazua")
