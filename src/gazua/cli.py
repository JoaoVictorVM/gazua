"""Command line interface."""

import sys
from collections.abc import Generator
from contextlib import contextmanager
from enum import StrEnum
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Annotated, Any, Literal

import typer

EXIT_USAGE = 2
DEFAULT_CONFIG = Path("gazua.yaml")
RUN_CHOICE_MESSAGE = (
    "Choose what to run: gazua run --tools runs the attacks; to read the catalog, "
    "use gazua run --list."
)

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


def _usage_error(message: str) -> typer.Exit:
    _say(message, err=True)
    return typer.Exit(EXIT_USAGE)


def _list_catalog(
    config_path: Path | None,
    mode: Literal["tools", "agent"] | None,
    mold: str | None,
    language: Literal["en", "pt"],
) -> None:
    from dataclasses import replace

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
    if mold is not None:
        entries = tuple(entry for entry in result.entries if entry.id == mold)
        if not entries:
            raise _usage_error("No mold with this id; see gazua run --list.")
        result = replace(result, entries=entries)
    for line in render_listing(result, config, mode=mode, language=language):
        _say(line)
    if config is None:
        _say(NO_CONFIG_NOTE)
    for diagnostic in result.diagnostics:
        _say(diagnostic.render(), err=True)
    if result.has_errors:
        raise typer.Exit(EXIT_USAGE)


def _run_tools(config_path: Path, mold: str | None, language: str, limits: dict[str, Any]) -> None:
    from pydantic import ValidationError

    from gazua.catalog.loader import load_catalog
    from gazua.config.diagnostics import ConfigError
    from gazua.config.loader import load_config
    from gazua.modes.tools import HTTP_REFUSAL, ToolsPreview, run_tools, tools_molds
    from gazua.modes.tools_models import ToolsOptions
    from gazua.modes.tools_presentation import inventory_lines, result_lines
    from gazua.runtime.run_models import LimitOverrides, Progress, RunEvent

    if not config_path.is_file():
        raise _usage_error(
            "No configuration at this path. Create one with gazua init, or pass --config."
        )
    try:
        config = load_config(config_path).config
    except ConfigError as error:
        if any(item.code == "http_target" for item in error.diagnostics):
            raise _usage_error(HTTP_REFUSAL) from None
        for diagnostic in error.diagnostics:
            _say(diagnostic.render(), err=True)
        raise typer.Exit(EXIT_USAGE) from None
    catalog = load_catalog(
        config,
        config_dir=config_path.parent,
        on_warning=lambda warning: _say(warning.message, err=True),
    )
    if catalog.has_errors:
        for diagnostic in catalog.diagnostics:
            _say(diagnostic.render(), err=True)
        raise typer.Exit(EXIT_USAGE)
    with exit_on_config_error():
        tools_molds(catalog.entries, mold)
    if config.entrypoint is None:
        raise _usage_error(
            "Tools mode imports the entrypoint's module to find the tools; declare entrypoint."
        )
    try:
        overrides = LimitOverrides.model_validate(limits)
    except ValidationError:
        raise _usage_error("Limit options must be positive numbers.") from None
    options = ToolsOptions(
        mold=mold,
        language="pt" if language == "pt" else "en",
        overrides=overrides,
        config_path=str(config_path),
    )

    def show_preview(preview: ToolsPreview) -> None:
        for line in inventory_lines(preview):
            _say(line)

    def show_progress(event: RunEvent) -> None:
        progress = getattr(event, "progress", None)
        if event.kind == "execution_finished" and isinstance(progress, Progress):
            _say(progress.text)

    try:
        with exit_on_config_error():
            result = run_tools(
                config,
                catalog.entries,
                options,
                config_path.parent.resolve(),
                on_preview=show_preview,
                on_event=show_progress,
            )
    except KeyboardInterrupt:
        raise _usage_error("Interrupted before any attack ran.") from None
    try:
        installed = version("gazua")
    except PackageNotFoundError:
        installed = None
    for line in result_lines(result, version=installed):
        _say(line)
    raise typer.Exit(result.exit_code)


@app.command(name="run")
def run_command(
    list_molds: Annotated[
        bool,
        typer.Option("--list", help="List the attack catalog. Nothing is executed."),
    ] = False,
    tools: Annotated[
        bool,
        typer.Option(
            "--tools",
            help="Call the tools directly as the attacker, with no model. With --list, list "
            "the tools molds only.",
        ),
    ] = False,
    config_path: Annotated[
        Path | None,
        typer.Option(
            "--config",
            metavar="PATH",
            help="Configuration to use. Defaults to ./gazua.yaml.",
            show_default=False,
        ),
    ] = None,
    mode: Annotated[
        ModeChoice | None,
        typer.Option("--mode", help="Show only the molds of one mode.", show_default=False),
    ] = None,
    mold: Annotated[
        str | None,
        typer.Option(
            "--mold", metavar="ID", help="Only this mold, by exact id.", show_default=False
        ),
    ] = None,
    language: Annotated[
        LanguageChoice,
        typer.Option("--language", help="Language of the listing labels and attack text."),
    ] = LanguageChoice.en,
    max_runs: Annotated[
        int | None,
        typer.Option("--max-runs", min=1, help="Most executions to start.", show_default=False),
    ] = None,
    timeout: Annotated[
        float | None,
        typer.Option(
            "--timeout",
            help="Seconds per execution.",
            show_default=False,
        ),
    ] = None,
    max_tool_calls: Annotated[
        int | None,
        typer.Option(
            "--max-tool-calls", min=1, help="Tool calls per execution.", show_default=False
        ),
    ] = None,
    concurrency: Annotated[
        int | None,
        typer.Option(
            "--concurrency", min=1, help="Executions at the same time.", show_default=False
        ),
    ] = None,
    max_cost: Annotated[
        float | None,
        typer.Option(
            "--max-cost",
            help="Cost ceiling in USD, as in gazua.yaml.",
            show_default=False,
        ),
    ] = None,
) -> None:
    """Run the attacks in tools mode, or list the attack catalog by damage and mode."""
    limits: dict[str, Any] = {
        name: value
        for name, value in (
            ("max_runs", max_runs),
            ("timeout", timeout),
            ("max_tool_calls", max_tool_calls),
            ("concurrency", concurrency),
            ("max_cost", max_cost),
        )
        if value is not None
    }
    if tools and mode is ModeChoice.agent:
        raise _usage_error("--tools runs tools mode; --mode agent conflicts with it.")
    if list_molds:
        if limits:
            raise _usage_error("--list only reads the catalog; limit options apply to --tools.")
        listed: Literal["tools", "agent"] | None = None
        if tools or mode is ModeChoice.tools:
            listed = "tools"
        elif mode is ModeChoice.agent:
            listed = "agent"
        _list_catalog(config_path, listed, mold, "pt" if language is LanguageChoice.pt else "en")
        return
    if not tools:
        raise _usage_error(RUN_CHOICE_MESSAGE)
    path = config_path if config_path is not None else DEFAULT_CONFIG
    _run_tools(path, mold, language.value, limits)


def main() -> int:
    app(prog_name="gazua")
    return 0
