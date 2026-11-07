from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

Spy = Callable[..., dict[str, Any]]

RUNTIME_PATHS = [
    pytest.param(("import",), 0, id="import"),
    pytest.param(("cli", "--help"), 0, id="help"),
    pytest.param(("cli", "--version"), 0, id="version"),
    pytest.param(("cli",), 0, id="bare"),
    pytest.param(("cli", "run"), 2, id="rejected-command"),
]


def test_spy_detects_network_and_credential_access(run_spied: Spy) -> None:
    report = run_spied("control")

    assert "socket.getaddrinfo" in report["network"]
    assert "socket.connect" in report["network"]
    assert report["credential_reads"] == ["OPENAI_API_KEY"]


@pytest.mark.parametrize(("target", "exit_code"), RUNTIME_PATHS)
def test_import_help_version_do_not_open_network(
    run_spied: Spy, target: tuple[str, ...], exit_code: int
) -> None:
    report = run_spied(*target)

    assert report["exit_code"] == exit_code
    assert report["network"] == []


@pytest.mark.parametrize(("target", "exit_code"), RUNTIME_PATHS)
def test_cli_does_not_access_provider_credentials(
    run_spied: Spy, target: tuple[str, ...], exit_code: int
) -> None:
    report = run_spied(*target)

    assert report["exit_code"] == exit_code
    assert report["credential_reads"] == []
    assert report["environment_listed"] is False


@pytest.mark.parametrize(("target", "exit_code"), RUNTIME_PATHS)
def test_cli_does_not_write_working_directory(
    run_spied: Spy, workdir: Path, target: tuple[str, ...], exit_code: int
) -> None:
    report = run_spied(*target)

    assert report["exit_code"] == exit_code
    assert list(workdir.iterdir()) == []
