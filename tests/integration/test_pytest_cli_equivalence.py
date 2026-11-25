import json
import sys

import pytest
from ci_support import plain_run
from pytest_gazua_support import tools_project

from conftest import run_process
from gazua.ci.projection import project
from gazua.pytest_models import MoldResult
from gazua.reports.storage import load_run_document

pytest_plugins = ("pytester",)


def test_pytest_and_cli_share_finding_id_state_severity_and_gate(
    pytester: pytest.Pytester,
) -> None:
    tools_project(pytester)
    cli = run_process(
        [sys.executable, "-m", "gazua", "run", "--tools", "--mold", "idor-01"], cwd=pytester.path
    )
    assert cli.returncode == 1
    [cli_finding] = load_run_document(pytester.path / ".gazua" / "run.json").findings

    result = pytester.runpytest_subprocess(
        "--gazua", "--gazua-mold", "idor-01", "-p", "no:cacheprovider"
    )

    assert result.ret == pytest.ExitCode.TESTS_FAILED
    plugin_run = load_run_document(pytester.path / ".gazua" / "run.json")
    [plugin_finding] = plugin_run.findings
    assert (plugin_finding.id, plugin_finding.severity, plugin_finding.gated) == (
        cli_finding.id,
        cli_finding.severity,
        cli_finding.gated,
    )
    assert plugin_run.report_exit_code == cli.returncode
    assert {item.state for item in plugin_run.verdicts.results} == {"finding"}
    text = result.stdout.str()
    assert f"Gazua finding {cli_finding.id}: {cli_finding.severity} {cli_finding.damage}" in text
    assert " ".join(cli_finding.reproduction.argv) in text


def test_pytest_does_not_rejudge_upper_bound() -> None:
    run = plain_run()
    [result] = [item for item in run.verdicts.results if item.state == "finding"]
    summary = project(run)
    gated = MoldResult("idor-02", run.run_id, 1, tuple(summary.findings), 1, 1, 1)
    quiet = tuple(item.model_copy(update={"effective_gated": False}) for item in summary.findings)

    assert result.upper_bound is not None
    assert gated.state()[0] == "failed"
    assert MoldResult("idor-02", run.run_id, 0, quiet, 1, 1, 1).state()[0] == "xfailed"


def test_pytest_failure_has_no_attack_text(pytester: pytest.Pytester) -> None:
    tools_project(pytester)

    result = pytester.runpytest_subprocess(
        "--gazua", "--gazua-mold", "idor-01", "-p", "no:cacheprovider", "-vv"
    )

    run = load_run_document(pytester.path / ".gazua" / "run.json")
    text = result.stdout.str() + result.stderr.str()
    for scenario in run.scenarios:
        assert scenario.attack not in text
        assert json.dumps(scenario.payload) not in text
    assert "GAZUA-CANARY-7f3a9c" not in text
    assert "order-victim-1" not in text
