"""Command line interface."""

import sys
from collections.abc import Generator
from contextlib import contextmanager
from enum import StrEnum
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Annotated

import typer

EXIT_USAGE = 2
DEFAULT_CONFIG = Path("gazua.yaml")
LIST_ONLY_MESSAGE = "Only catalog listing is available in this version; use gazua run --list."

# Plain rendering keeps help and errors free of Rich panels, whose box drawing depends on
# the terminal encoding, and of tracebacks that print local variables.
app = typer.Typer(
    add_completion=False,
    pretty_exceptions_enable=False,
    rich_markup_mode=None,
)


def _print_version(requested: bool) -> None:
    if not requested:
        return
    try:
        installed = version("gazua")
    except PackageNotFoundError:
        typer.echo(
            "Gazua's package metadata is missing, so this installation is broken. "
            "Reinstall it with pip or uv.",
            err=True,
        )
        raise typer.Exit(EXIT_USAGE) from None
    typer.echo(f"gazua {installed}")
    raise typer.Exit


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    _version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Show the installed version and exit.",
            callback=_print_version,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """Security test suite for AI agents: proves in code whether an attack had a real effect."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


def _safe_for_stream(text: str, err: bool) -> str:
    # Piped output on Windows uses a legacy code page that cannot encode every project name.
    stream = sys.stderr if err else sys.stdout
    encoding = getattr(stream, "encoding", None) or "utf-8"
    return text.encode(encoding, "backslashreplace").decode(encoding)


def _say(text: str, *, err: bool = False) -> None:
    typer.echo(_safe_for_stream(text, err), err=err)


@contextmanager
def exit_on_config_error() -> Generator[None, None, None]:
    """Turns configuration failures into their diagnostics and the usage exit code."""
    from gazua.config.diagnostics import ConfigError

    try:
        yield
    except ConfigError as error:
        for diagnostic in error.diagnostics:
            _say(diagnostic.render(), err=True)
        raise typer.Exit(EXIT_USAGE) from None


@app.command()
def init(
    directory: Annotated[
        Path,
        typer.Argument(
            help="Root of the project to prepare. Defaults to the current directory.",
            show_default=False,
        ),
    ] = Path(),
    entrypoint: Annotated[
        str | None,
        typer.Option(
            "--entrypoint",
            metavar="MODULE:ATTRIBUTE",
            help="Test entrypoint to record. It is checked for syntax, never imported.",
        ),
    ] = None,
) -> None:
    """Create gazua.yaml from the tools found in a project, for human review."""
    from gazua.config.diagnostics import sanitize
    from gazua.project_init import check_target, initialize_project, suggests_sensitive

    with exit_on_config_error():
        check_target(directory)
        _say(
            "Warning: Python references in gazua.yaml can execute code in a future execution. "
            "Review them as code.",
            err=True,
        )
        result = initialize_project(directory, entrypoint)

    tools = result.discovery.tools
    if tools:
        _say("Discovered tools (suggestions, review required):")
        for tool in tools:
            suggestion = "sensitive" if suggests_sensitive(tool.name) else "not classified"
            _say(f"  {sanitize(tool.name)}: {suggestion}")
    else:
        _say("No tools were discovered.")
    for warning in result.warnings:
        _say(f"Warning: {warning.render()}", err=True)
    if any(tool.source == "decorator" for tool in tools):
        _say(
            "Note: @gazua.tool needs gazua installed in production. Prefer gazua.wrap in a test "
            "entrypoint so production code imports nothing from Gazua (docs/integration.md)."
        )

    _say(f"Created {sanitize(str(result.config_path))}")
    if result.gitignore_changed:
        _say(f"Added .gazua/ to {sanitize(str(result.gitignore_path))}")
    else:
        _say(f"{sanitize(str(result.gitignore_path))} already ignores .gazua/")
    _say("Tools were read from the source code. They were not imported or verified.")
    if not result.discovery.complete:
        _say("Discovery was incomplete: declare any missing tool manually.")
    missing = [
        label
        for label, absent in (("entrypoint", result.entrypoint is None), ("tools", not tools))
        if absent
    ]
    if missing:
        _say(f"This configuration is not ready to run yet. Declare: {', '.join(missing)}.")
    _say("Review every REVIEW REQUIRED comment before relying on this file.")


class ModeChoice(StrEnum):
    tools = "tools"
    agent = "agent"


class LanguageChoice(StrEnum):
    en = "en"
    pt = "pt"


@app.command(name="run")
def run_command(
    list_molds: Annotated[
        bool,
        typer.Option("--list", help="List the attack catalog. Nothing is executed."),
    ] = False,
    config_path: Annotated[
        Path | None,
        typer.Option(
            "--config",
            metavar="PATH",
            help="Configuration to check requirements against. Defaults to ./gazua.yaml.",
            show_default=False,
        ),
    ] = None,
    mode: Annotated[
        ModeChoice | None,
        typer.Option("--mode", help="Show only the molds of one mode.", show_default=False),
    ] = None,
    language: Annotated[
        LanguageChoice,
        typer.Option("--language", help="Language of the listing labels."),
    ] = LanguageChoice.en,
) -> None:
    """List the attack catalog by damage and mode. Running attacks is not available yet."""
    if not list_molds:
        _say(LIST_ONLY_MESSAGE, err=True)
        raise typer.Exit(EXIT_USAGE)

    from gazua.catalog.listing import NO_CONFIG_NOTE, render_listing
    from gazua.catalog.loader import load_catalog
    from gazua.config.loader import load_config

    path = config_path if config_path is not None else DEFAULT_CONFIG
    config = None
    if config_path is not None or DEFAULT_CONFIG.exists():
        with exit_on_config_error():
            config = load_config(path).config
    result = load_catalog(
        config,
        config_dir=path.parent,
        on_warning=lambda warning: _say(warning.message, err=True),
    )
    for line in render_listing(
        result, config, mode=None if mode is None else mode.value, language=language.value
    ):
        _say(line)
    if config is None:
        _say(NO_CONFIG_NOTE)
    for diagnostic in result.diagnostics:
        _say(diagnostic.render(), err=True)
    if result.has_errors:
        raise typer.Exit(EXIT_USAGE)


def main() -> int:
    app(prog_name="gazua")
    return 0
