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


NO_REDACT_IN_CI = (
    "--no-redact is refused in CI: masking cannot be turned off there. Run it locally."
)
NO_REDACT_LOCAL = (
    "Warning: --no-redact keeps secrets and personal data in .gazua/ and in the reports of "
    "this run. Do not share or commit them."
)
GITIGNORE_WARNING = (
    "Warning: .gazua/ is not in this project's .gitignore, so evidence could be committed. "
    "Add .gazua/ to .gitignore."
)
LOCK_BUSY = "Another Gazua command is using .gazua/ in this project. Try again when it finishes."
STORAGE_UNAVAILABLE = (
    "Cannot write to .gazua/ in the project folder: no attack was run. The full summary follows."
)
LOAD_MESSAGES = {
    "run_file_not_found": "No run.json at this path.",
    "run_file_too_large": "This run.json is larger than 64 MiB.",
    "run_file_too_deep": "This run.json nests deeper than 64 levels.",
    "run_file_invalid_json": "This file is not valid JSON.",
    "run_schema_version_unsupported": (
        "This run.json uses a schema version this Gazua does not know; it needs a migration "
        "to schema_version 1."
    ),
    "run_file_invalid": "This run.json does not follow the run schema.",
}


def _refuse_no_redact_in_ci(no_redact: bool) -> None:
    import os

    from gazua.reports.redaction import running_in_ci

    if no_redact and running_in_ci(os.environ):
        raise _usage_error(NO_REDACT_IN_CI)


def _installed_version() -> str | None:
    try:
        return version("gazua")
    except PackageNotFoundError:
        return None


def _say_lines(lines: list[str], *, err: bool = False) -> None:
    from gazua.reports.terminal import clean_terminal

    for line in lines:
        _say(clean_terminal(line), err=err)


def _load_tools_config(config_path: Path) -> Any:
    from gazua.config.diagnostics import ConfigError
    from gazua.config.loader import load_config
    from gazua.modes.tools import HTTP_REFUSAL

    if not config_path.is_file():
        raise _usage_error(
            "No configuration at this path. Create one with gazua init, or pass --config."
        )
    try:
        return load_config(config_path).config
    except ConfigError as error:
        if any(item.code == "http_target" for item in error.diagnostics):
            raise _usage_error(HTTP_REFUSAL) from None
        for diagnostic in error.diagnostics:
            _say(diagnostic.render(), err=True)
        raise typer.Exit(EXIT_USAGE) from None


def _run_tools(
    config_path: Path,
    mold: str | None,
    language: str,
    limits: dict[str, Any],
    no_redact: bool = False,
) -> None:
    from pydantic import ValidationError

    from gazua.catalog.loader import load_catalog
    from gazua.modes.tools import tools_molds
    from gazua.modes.tools_models import ToolsOptions
    from gazua.reports.lifecycle import LifecycleLock, LockBusy, gitignore_covers
    from gazua.runtime.run_models import LimitOverrides

    config = _load_tools_config(config_path)
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
    project_root = config_path.parent.resolve()
    options = ToolsOptions(
        mold=mold,
        language="pt" if language == "pt" else "en",
        overrides=overrides,
        config_path=config_path.name,
    )
    if no_redact:
        _say(NO_REDACT_LOCAL, err=True)
    if not gitignore_covers(project_root):
        _say(GITIGNORE_WARNING, err=True)
    lock: LifecycleLock | None = LifecycleLock(project_root)
    try:
        lock.__enter__()  # type: ignore[union-attr]
    except LockBusy:
        raise _usage_error(LOCK_BUSY) from None
    except OSError:
        lock = None
    try:
        code = _execute_tools(
            config, catalog.entries, options, project_root, lock is not None, no_redact
        )
    finally:
        if lock is not None:
            lock.__exit__(None, None, None)
    raise typer.Exit(code)


def _execute_tools(
    config: Any, entries: Any, options: Any, project_root: Path, locked: bool, no_redact: bool
) -> int:
    from datetime import UTC, datetime

    from gazua.modes.tools import ToolsPreview, run_tools
    from gazua.modes.tools_presentation import diagnostic_lines, inventory_lines
    from gazua.reports.builder import build_run_document
    from gazua.reports.capture import ReportEvidenceCollector
    from gazua.reports.redaction import EngineRedaction, ReportRedactionPolicy, ReportRedactor
    from gazua.reports.rendering import render_report, terminal_lines
    from gazua.reports.storage import StorageError, save_run, storage_ready
    from gazua.runtime.run_models import Progress, RunEvent

    def show_preview(preview: ToolsPreview) -> None:
        for line in inventory_lines(preview):
            _say(line)

    def show_progress(event: RunEvent) -> None:
        progress = getattr(event, "progress", None)
        if event.kind == "execution_finished" and isinstance(progress, Progress):
            _say(progress.text)

    ready = locked and storage_ready(project_root)
    if not ready:
        _say(STORAGE_UNAVAILABLE, err=True)
    redactor = ReportRedactor(ReportRedactionPolicy.from_config(config, no_redact=no_redact))
    capture = ReportEvidenceCollector(redactor)
    created_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    try:
        with exit_on_config_error():
            result = run_tools(
                config,
                entries,
                options,
                project_root,
                on_preview=show_preview,
                on_event=show_progress,
                on_evidence=capture,
                evidence_redactor=EngineRedaction(redactor),
                storage_available=ready,
            )
    except KeyboardInterrupt:
        raise _usage_error("Interrupted before any attack ran.") from None
    document = build_run_document(
        run_id=result.run_id,
        created_at=created_at,
        target_ref=config.entrypoint,
        mode="tools",
        language=options.language,
        engine=result.engine,
        verdicts=result.verdicts,
        contexts=result.contexts,
        reproduction=result.reproduction,
        treatment=redactor,
        exit_code=result.exit_code,
        config=config,
        excerpts=capture,
        gazua_version=_installed_version(),
        diagnostics=capture.diagnostics(),
    )
    _say_lines(terminal_lines(document))
    _say_lines(diagnostic_lines(result))
    if not ready:
        return 2
    try:
        html, markdown = render_report(document)
        saved = save_run(project_root, document, html, markdown)
    except StorageError as error:
        _say(
            f"The reports could not be written ({error.code.replace('_', ' ')}); the summary "
            "above is complete and the previous reports were kept.",
            err=True,
        )
        return 2
    for diagnostic in saved.diagnostics:
        _say(f"Retention: {diagnostic.code.replace('_', ' ')}.", err=True)
    _say(f"Reports: {saved.paths['html']}, {saved.paths['markdown']}, {saved.paths['json']}")
    _say(f"Archived as {saved.paths['archive']}; the last {saved.retained_runs} runs are kept.")
    return max(document.report_exit_code, saved.exit_code)


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
    no_redact: Annotated[
        bool,
        typer.Option(
            "--no-redact",
            help="Keep captured evidence unmasked in this local run. Refused in CI.",
        ),
    ] = False,
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
    _refuse_no_redact_in_ci(no_redact)
    if list_molds:
        if no_redact:
            raise _usage_error("--list only reads the catalog; --no-redact applies to --tools.")
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
    _run_tools(path, mold, language.value, limits, no_redact)


@app.command(name="report")
def report_command(
    source_text: Annotated[
        str,
        typer.Option(
            "--from",
            metavar="PATH",
            help="A local run.json to rebuild the reports from. Nothing is executed.",
            show_default=False,
        ),
    ],
    no_redact: Annotated[
        bool,
        typer.Option(
            "--no-redact",
            help="Accept a run.json captured with --no-redact. Refused in CI.",
        ),
    ] = False,
) -> None:
    """Rebuild report.html and report.md in ./.gazua from a run.json, offline."""
    from gazua.reports.lifecycle import LifecycleLock, LockBusy
    from gazua.reports.rendering import render_report, terminal_lines
    from gazua.reports.storage import (
        RunLoadError,
        StorageError,
        parse_run_document,
        publish_regenerated,
        read_run_bytes,
    )

    _refuse_no_redact_in_ci(no_redact)
    text = source_text
    if "://" in text:
        raise _usage_error("--from takes a local run.json path, not a URL.")
    source = Path(text)
    try:
        content = read_run_bytes(source)
        document = parse_run_document(content)
    except RunLoadError as error:
        raise _usage_error(LOAD_MESSAGES.get(error.code, "This run.json cannot be read.")) from None
    if document.redaction == "none" and not no_redact:
        raise _usage_error(
            "This run.json was captured with --no-redact. Pass --no-redact to rebuild its "
            "reports locally."
        )
    root = Path.cwd()
    try:
        with LifecycleLock(root):
            html, markdown = render_report(document)
            paths = publish_regenerated(root, source.resolve(), content, html, markdown)
    except LockBusy:
        raise _usage_error(LOCK_BUSY) from None
    except (StorageError, OSError):
        raise _usage_error(
            "The reports could not be written to .gazua/; the previous reports were kept."
        ) from None
    if document.redaction == "none":
        _say(NO_REDACT_LOCAL, err=True)
    _say_lines(terminal_lines(document))
    _say_lines([f"Rebuilt from {text} (run {document.run_id})."])
    _say(f"Reports: {paths['html']}, {paths['markdown']}, {paths['json']}")


@app.command(name="clean")
def clean_command() -> None:
    """Remove Gazua's runs, reports and evidence from ./.gazua. Unknown files stay."""
    from gazua.reports.lifecycle import LifecycleLock, LockBusy, clean_runs

    root = Path.cwd()
    if not (root / ".gazua").is_dir():
        _say("Removed 0 runs and 0 report files.")
        return
    try:
        with LifecycleLock(root):
            result = clean_runs(root)
    except LockBusy:
        raise _usage_error(LOCK_BUSY) from None
    except OSError:
        raise _usage_error("Cannot use .gazua/ in this folder.") from None
    _say(f"Removed {result.runs} runs and {result.files} report files.")
    if result.pending:
        _say("Could not remove these, check their permissions:", err=True)
        _say_lines([f"  {item}" for item in result.pending], err=True)
        raise typer.Exit(2)


def main() -> int:
    app(prog_name="gazua")
    return 0
