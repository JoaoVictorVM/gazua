import pytest
from ci_support import plain_run, run_with_baseline
from pytest_gazua_support import tools_project

from gazua.catalog.loader import load_catalog
from gazua.ci.projection import project
from gazua.config.loader import load_config
from gazua.modes.tools import tools_molds
from gazua.pytest_models import GazuaOptions, MoldResult

pytest_plugins = ("pytester",)

FAKE_XDIST = """
def pytest_addoption(parser):
    parser.addoption("--numprocesses", dest="numprocesses", default=None)
"""


def test_plugin_is_inert_without_flag(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(test_regular="def test_regular():\n    assert True\n")
    (pytester.path / "gazua.yaml").write_text("not: [valid", encoding="utf-8")

    result = pytester.runpytest("-p", "no:cacheprovider")

    result.assert_outcomes(passed=1)
    assert "gazua::" not in result.stdout.str()
    assert not (pytester.path / ".gazua").exists()


def test_one_item_per_selected_mold(pytester: pytest.Pytester) -> None:
    tools_project(pytester)

    chosen = pytester.runpytest(
        "--gazua", "--gazua-mold", "idor-02", "--gazua-mold", "idor-01", "--collect-only", "-q"
    )
    every = pytester.runpytest("--gazua", "--collect-only", "-q")

    lines = [line for line in chosen.stdout.lines if line.startswith("gazua::")]
    assert lines == ["gazua::idor-01", "gazua::idor-02"]
    config = load_config(pytester.path / "gazua.yaml").config
    expected = [
        mold.id for mold in tools_molds(load_catalog(config, config_dir=pytester.path).entries)
    ]
    listed = [
        line.removeprefix("gazua::") for line in every.stdout.lines if line.startswith("gazua::")
    ]
    assert listed == expected
    assert "test_regular.py::test_regular" in every.stdout.str()
    assert not (pytester.path / "effects").exists()


def test_unknown_mold_fails_collection(pytester: pytest.Pytester) -> None:
    tools_project(pytester)

    result = pytester.runpytest("--gazua", "--gazua-mold", "no-such-mold")

    assert result.ret == pytest.ExitCode.USAGE_ERROR
    assert "No mold with this id supports tools mode" in result.stderr.str()
    assert not (pytester.path / "effects").exists()
    assert not (pytester.path / ".gazua").exists()


def test_xdist_is_refused_before_run(pytester: pytest.Pytester) -> None:
    tools_project(pytester)
    pytester.makeconftest(FAKE_XDIST)

    result = pytester.runpytest("--gazua", "--gazua-mold", "idor-01", "--numprocesses", "2")
    single = pytester.runpytest(
        "--gazua", "--gazua-mold", "idor-01", "--numprocesses", "0", "--collect-only"
    )

    assert result.ret == pytest.ExitCode.USAGE_ERROR
    assert "pytest_gazua_xdist_unsupported" in result.stderr.str()
    assert "-n0" in result.stderr.str()
    assert not (pytester.path / "effects").exists()
    assert single.ret == pytest.ExitCode.OK


def test_duplicate_selection_is_deduplicated(pytester: pytest.Pytester) -> None:
    tools_project(pytester)

    result = pytester.runpytest(
        "--gazua", "--gazua-mold", "idor-01", "--gazua-mold", "idor-01", "--collect-only", "-q"
    )

    assert [line for line in result.stdout.lines if line.startswith("gazua::")] == [
        "gazua::idor-01"
    ]
    assert GazuaOptions(True, pytester.path, ("a", "b", "a"), None).selected() == ("a", "b")


def _result(**counts: int) -> MoldResult:
    return MoldResult("idor-01", "GAZUA-run-1", 0, (), **counts)  # type: ignore[arg-type]


def test_state_mapping_uses_the_native_result() -> None:
    gated = project(plain_run()).findings
    known = project(run_with_baseline("open")).findings
    not_gated = (gated[0].model_copy(update={"effective_gated": False}),)

    assert MoldResult("m", "GAZUA-run-1", 1, gated, 0, 0, 0).state()[0] == "failed"
    assert MoldResult("m", "GAZUA-run-1", 0, known, 0, 0, 0).state() == (
        "xfailed",
        "gazua_known_finding",
    )
    assert MoldResult("m", "GAZUA-run-1", 0, not_gated, 0, 0, 0).state() == (
        "xfailed",
        "gazua_finding_not_gated",
    )
    assert _result(resisted=1, not_tested=1, not_applicable=0).state()[0] == "passed"
    assert _result(resisted=0, not_tested=2, not_applicable=1).state() == (
        "skipped",
        "gazua_not_tested",
    )
    assert _result(resisted=0, not_tested=0, not_applicable=3).state() == (
        "skipped",
        "gazua_not_applicable",
    )
