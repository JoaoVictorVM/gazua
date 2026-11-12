from pathlib import Path

import pytest
from report_support import CI_VARIABLES, echo_project, gazua, local_environment, read_json

from gazua.reports.rendering import NO_REDACT_WARNING

PLANTED = "ghp_" + "Qx7Lm2Rt9Wv4Yz8Kp3Nb6Hc1Jd5Fg0Sa2Ue7"


@pytest.mark.parametrize("variable", CI_VARIABLES)
def test_ci_refuses_before_target_import(tmp_path: Path, variable: str) -> None:
    project = echo_project(tmp_path / "project")
    (project / "echo_target.py").write_text(
        "from pathlib import Path\nPath('imported').write_text('x')\n", encoding="utf-8"
    )

    result = gazua(
        project, "run", "--tools", "--no-redact", env=local_environment(**{variable: "True"})
    )

    assert result.returncode == 2
    assert "--no-redact is refused in CI" in result.stderr
    assert not (project / "imported").exists()
    assert not (project / ".gazua").exists()


def test_local_warns_and_ci_refuses_before_target_import(tmp_path: Path) -> None:
    project = echo_project(tmp_path / "project")
    environment = local_environment(GAZUA_TEST_ECHO=PLANTED, CI="false")

    local = gazua(project, "run", "--tools", "--mold", "idor-01", "--no-redact", env=environment)

    assert local.returncode == 1, local.stderr
    assert "--no-redact keeps secrets" in local.stderr
    assert NO_REDACT_WARNING in local.stdout
    run_path = project / ".gazua" / "run.json"
    run = read_json(run_path)
    assert run["redaction"] == "none"
    assert run["proofs"][0]["content"]["original"]["note"] == PLANTED
    assert "--no-redact" not in run["findings"][0]["reproduction"]["argv"]
    assert NO_REDACT_WARNING in (project / ".gazua" / "report.html").read_text(encoding="utf-8")

    plain = gazua(project, "report", "--from", str(run_path))
    in_ci = gazua(
        project,
        "report",
        "--from",
        str(run_path),
        "--no-redact",
        env=local_environment(GITHUB_ACTIONS="true"),
    )
    allowed = gazua(project, "report", "--from", str(run_path), "--no-redact")

    assert plain.returncode == 2
    assert "Pass --no-redact" in plain.stderr
    assert in_ci.returncode == 2
    assert "refused in CI" in in_ci.stderr
    assert allowed.returncode == 0, allowed.stderr
    assert "--no-redact keeps secrets" in allowed.stderr

    masked = echo_project(tmp_path / "masked")
    assert gazua(masked, "run", "--tools", "--mold", "idor-01", env=environment).returncode == 1
    masked_run = masked / ".gazua" / "run.json"
    recovered = gazua(masked, "report", "--from", str(masked_run), "--no-redact")
    assert recovered.returncode == 0, recovered.stderr
    shown = (masked / ".gazua" / "report.html").read_text(encoding="utf-8")
    assert PLANTED not in shown
    assert "[redacted-secret]" in shown
    assert gazua(masked, "run", "--list", "--no-redact").returncode == 2
