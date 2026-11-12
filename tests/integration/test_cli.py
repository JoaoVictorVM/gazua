import contextlib
import re
import subprocess
import tempfile
import tomllib
from importlib import metadata
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from typer.testing import CliRunner

from gazua import cli

DEFERRED_COMMANDS = ("demo", "baseline", "verify")

unknown_options = st.from_regex(r"--[a-z][a-z0-9-]{0,20}", fullmatch=True).filter(
    lambda option: option not in {"--help", "--version"}
)


def execute(command: list[str], *arguments: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*command, *arguments], cwd=cwd, capture_output=True, text=True, timeout=60, check=False
    )


def test_help_lists_only_delivered_commands(
    entrypoints: dict[str, list[str]], workdir: Path
) -> None:
    result = execute(entrypoints["console script"], "--help", cwd=workdir)
    module = execute(entrypoints["module"], "--help", cwd=workdir)

    assert result.returncode == 0
    assert module.stdout == result.stdout
    assert "Security test suite for AI agents" in result.stdout
    assert "--help" in result.stdout
    assert "--version" in result.stdout
    assert re.search(r"\binit\b", result.stdout)
    assert re.search(r"\brun\b", result.stdout)
    for command in DEFERRED_COMMANDS:
        assert not re.search(rf"\b{command}\b", result.stdout), command


def test_version_matches_distribution_metadata(
    console_script: Path, project_root: Path, workdir: Path
) -> None:
    manifest = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))
    declared = manifest["project"]["version"]

    result = execute([str(console_script)], "--version", cwd=workdir)

    assert result.returncode == 0
    assert metadata.version("gazua") == declared
    assert result.stdout == f"gazua {declared}\n"
    assert result.stderr == ""


def test_no_arguments_shows_help(console_script: Path, workdir: Path) -> None:
    bare = execute([str(console_script)], cwd=workdir)
    explicit = execute([str(console_script)], "--help", cwd=workdir)

    assert bare.returncode == 0
    assert bare.stdout == explicit.stdout


@pytest.mark.parametrize(
    "arguments",
    [
        ("--version",),
        ("--help",),
        (),
        ("run",),
        ("run", "--list"),
        ("demo",),
        ("--opcao-inexistente",),
        ("init", "--help"),
    ],
    ids=["version", "help", "bare", "run", "run-list", "command", "option", "init-help"],
)
def test_module_and_console_entrypoints_agree(
    entrypoints: dict[str, list[str]], workdir: Path, arguments: tuple[str, ...]
) -> None:
    script = execute(entrypoints["console script"], *arguments, cwd=workdir)
    module = execute(entrypoints["module"], *arguments, cwd=workdir)

    assert (script.returncode, script.stdout, script.stderr) == (
        module.returncode,
        module.stdout,
        module.stderr,
    )


@pytest.mark.parametrize("argument", ["demo", "--opcao-inexistente"])
def test_unsupported_argument_reports_usage_on_stderr(
    console_script: Path, workdir: Path, argument: str
) -> None:
    result = execute([str(console_script)], argument, cwd=workdir)

    assert result.returncode == 2
    assert result.stdout == ""
    assert "Usage: gazua" in result.stderr
    assert "Traceback" not in result.stderr
    assert list(workdir.iterdir()) == []


@given(option=unknown_options)
def test_unknown_arguments_fail_without_traceback(option: str) -> None:
    with tempfile.TemporaryDirectory() as directory, contextlib.chdir(directory):
        result = CliRunner().invoke(cli.app, [option])
        created = list(Path(directory).iterdir())

    assert result.exit_code == 2
    assert isinstance(result.exception, SystemExit)
    assert "Traceback" not in result.output
    assert created == []


def test_missing_metadata_reports_broken_installation(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_metadata(_name: str) -> str:
        raise metadata.PackageNotFoundError

    monkeypatch.setattr(cli, "version", no_metadata)

    result = CliRunner().invoke(cli.app, ["--version"])

    assert result.exit_code == 2
    assert result.stdout == ""
    assert "Reinstall" in result.stderr
