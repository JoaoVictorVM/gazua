import sys

import pytest
from pytest_gazua_support import outcomes, tools_project

from conftest import run_process

pytest_plugins = ("pytester",)


def _gazua(pytester: pytest.Pytester, *arguments: str) -> pytest.RunResult:
    return pytester.runpytest_subprocess("--gazua", "-p", "no:cacheprovider", "-rA", *arguments)


def test_gated_mold_is_failed_with_cli_identity(pytester: pytest.Pytester) -> None:
    tools_project(pytester)

    result = _gazua(pytester, "--gazua-mold", "idor-01")

    assert outcomes(result) == {"passed": 1, "failed": 1}
    text = result.stdout.str()
    assert "FAILED gazua::idor-01" in text
    assert "high idor_via_agent in get_order (no baseline, gated)" in text
    assert "Reproduce: gazua run --tools --config gazua.yaml --mold idor-01" in text
    assert "Traceback" not in text


def test_known_finding_is_xfailed(pytester: pytest.Pytester) -> None:
    tools_project(pytester)
    command = [sys.executable, "-m", "gazua"]
    first = run_process([*command, "run", "--tools", "--mold", "idor-01"], cwd=pytester.path)
    assert first.returncode == 1, first.stderr
    accepted = run_process([*command, "baseline"], cwd=pytester.path)
    assert accepted.returncode == 0, accepted.stderr

    result = _gazua(pytester, "--gazua-mold", "idor-01")

    assert outcomes(result) == {"passed": 1, "xfailed": 1}
    assert "gazua_known_finding" in result.stdout.str()
    assert "(known, not gated)" in result.stdout.str()


def test_resisted_mold_passes(pytester: pytest.Pytester) -> None:
    tools_project(pytester)
    (pytester.path / "hardened").write_text("x", encoding="utf-8")

    result = _gazua(pytester, "--gazua-mold", "idor-01")

    assert outcomes(result) == {"passed": 2}
    assert "PASSED gazua::idor-01" in result.stdout.str()


def test_not_tested_and_not_applicable_skip(pytester: pytest.Pytester) -> None:
    tools_project(pytester)

    result = _gazua(pytester, "--gazua-mold", "idor-04")

    assert outcomes(result) == {"passed": 1, "skipped": 1}
    assert "gazua_not_applicable" in result.stdout.str()


def test_operational_failure_is_error(pytester: pytest.Pytester) -> None:
    tools_project(pytester, target={"reset": "tools_target:reset"})
    (pytester.path / "reset_fail").write_text("x", encoding="utf-8")

    result = _gazua(pytester, "--gazua-mold", "idor-01")

    assert outcomes(result) == {"passed": 1, "errors": 1}
    text = result.stdout.str()
    assert "ERROR gazua::idor-01" in text
    assert "Gazua reset_failed" in text
    assert "private detail" not in text
    assert "Traceback" not in text
