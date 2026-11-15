"""Command line interface."""

import sys
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Annotated, Any, Literal

import typer

EXIT_USAGE = 2
DEFAULT_CONFIG = Path("gazua.yaml")
RUN_CHOICE_MESSAGE = (
    "Choose what to run: gazua run --tools calls the tools directly, gazua run --agent sends "
    "the attacks to your agent; to read the catalog, use gazua run --list."
)
AGENT_HTTP_REFUSAL = (
    "--agent over HTTP is not available yet; point entrypoint to a Python test function."
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
        # Agent molds arrive with v0.2; the tools listing keeps its own release.
        release="v0.2" if mode == "agent" else None,
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
LOAD_MESSAGES = {
    "run_file_not_found": "No run.json at this path.",
    "run_file_too_large": "This run.json is larger than 64 MiB.",
    "run_file_too_deep": "This run.json nests deeper than 64 levels.",
    "run_file_invalid_json": "This file is not valid JSON.",
    "run_schema_version_unsupported": (
        "This run.json uses a schema version this Gazua does not know; it reads schema_version "
        "1 and 2, so it needs a migration."
    ),
    "run_file_invalid": "This run.json does not follow the run schema.",
}


def _refuse_no_redact_in_ci(no_redact: bool) -> None:
    import os

    from gazua.reports.redaction import running_in_ci

    if no_redact and running_in_ci(os.environ):
        raise _usage_error(NO_REDACT_IN_CI)


def _say_lines(lines: list[str], *, err: bool = False) -> None:
    from gazua.reports.terminal import clean_terminal

    for line in lines:
        _say(clean_terminal(line), err=err)


def _load_tools_config(config_path: Path, http_refusal: str | None = None) -> Any:
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
            raise _usage_error(http_refusal or HTTP_REFUSAL) from None
        for diagnostic in error.diagnostics:
            _say(diagnostic.render(), err=True)
        raise typer.Exit(EXIT_USAGE) from None


@dataclass(frozen=True, slots=True)
class BaselineChoice:
    """What run was told about the baseline: an explicit file, none, or the default if any."""

    path: Path | None = None
    disabled: bool = False


def _run_baseline(project_root: Path, config_path: Path, choice: BaselineChoice | None) -> Any:
    """The baseline a run compares with, read before the target is imported.

    Without flags the default file is used when it exists; an explicit file must exist. A
    file that exists but cannot be read is an error, never an empty baseline.
    """
    from gazua.baseline.models import BASELINE_FILE
    from gazua.baseline.storage import BaselineError, read_baseline, resolve_baseline_path

    chosen = choice or BaselineChoice()
    if chosen.disabled:
        return None
    try:
        path = resolve_baseline_path(
            project_root,
            chosen.path if chosen.path is not None else Path(BASELINE_FILE),
            config_path=config_path.resolve(),
        )
        return read_baseline(path)
    except BaselineError as error:
        if error.code == "baseline_missing" and chosen.path is None:
            return None
        raise _baseline_error(error) from None


def _run_tools(
    config_path: Path,
    mold: str | None,
    language: str,
    limits: dict[str, Any],
    no_redact: bool = False,
    choice: BaselineChoice | None = None,
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
        baseline = _run_baseline(project_root, config_path, choice)
        code = _execute_tools(
            config, catalog.entries, options, project_root, lock is not None, no_redact, baseline
        )
    finally:
        if lock is not None:
            lock.__exit__(None, None, None)
    raise typer.Exit(code)


def _report_output() -> Any:
    from gazua.reports.execution import ReportOutput

    return ReportOutput(
        say=_say,
        lines=lambda lines: _say_lines(list(lines)),
        warn=lambda text: _say(text, err=True),
    )


def _execute_tools(
    config: Any,
    entries: Any,
    options: Any,
    project_root: Path,
    locked: bool,
    no_redact: bool,
    baseline: Any = None,
) -> int:
    from gazua.reports.execution import execute_mode

    with exit_on_config_error():
        outcome = execute_mode(
            "tools",
            config,
            entries,
            options,
            project_root,
            _report_output(),
            locked=locked,
            no_redact=no_redact,
            baseline=baseline,
        )
    return outcome.exit_code


def _run_agent(
    config_path: Path,
    mold: str | None,
    quick: bool,
    language: str,
    limits: dict[str, Any],
    no_redact: bool = False,
    choice: BaselineChoice | None = None,
) -> None:
    from pydantic import ValidationError

    from gazua.catalog.loader import load_catalog
    from gazua.modes.agent import select_agent_molds
    from gazua.modes.agent_models import AgentOptions
    from gazua.reports.lifecycle import LifecycleLock, LockBusy, gitignore_covers
    from gazua.runtime.run_models import LimitOverrides

    config = _load_tools_config(config_path, AGENT_HTTP_REFUSAL)
    catalog = load_catalog(
        config,
        config_dir=config_path.parent,
        on_warning=lambda warning: _say(warning.message, err=True),
        release="v0.2",
    )
    if catalog.has_errors:
        for diagnostic in catalog.diagnostics:
            _say(diagnostic.render(), err=True)
        raise typer.Exit(EXIT_USAGE)
    with exit_on_config_error():
        select_agent_molds(catalog.entries, AgentOptions(mold=mold, quick=quick))
    if config.entrypoint is None:
        raise _usage_error("Agent mode sends messages to the entrypoint; declare entrypoint.")
    try:
        overrides = LimitOverrides.model_validate(limits)
    except ValidationError:
        raise _usage_error("Limit options must be positive numbers.") from None
    project_root = config_path.parent.resolve()
    options = AgentOptions(
        mold=mold,
        quick=quick,
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
        baseline = _run_baseline(project_root, config_path, choice)
        code = _execute_agent(
            config, catalog.entries, options, project_root, lock is not None, no_redact, baseline
        )
    finally:
        if lock is not None:
            lock.__exit__(None, None, None)
    raise typer.Exit(code)


def _execute_agent(
    config: Any,
    entries: Any,
    options: Any,
    project_root: Path,
    locked: bool,
    no_redact: bool,
    baseline: Any = None,
) -> int:
    from gazua.reports.execution import execute_mode

    with exit_on_config_error():
        outcome = execute_mode(
            "agent",
            config,
            entries,
            options,
            project_root,
            _report_output(),
            locked=locked,
            no_redact=no_redact,
            baseline=baseline,
        )
    return outcome.exit_code


def _check_run_options(
    *,
    list_molds: bool,
    tools: bool,
    agent: bool,
    quick: bool,
    mode: ModeChoice | None,
    no_redact: bool,
    limits: dict[str, Any],
    baseline: Path | None = None,
    no_baseline: bool = False,
) -> None:
    """Contradictory selections fail before any configuration or target is read."""
    if baseline is not None and no_baseline:
        raise _usage_error("--baseline and --no-baseline contradict each other; choose one.")
    if tools and agent:
        raise _usage_error("--tools and --agent are different modes; choose one.")
    if tools and mode is ModeChoice.agent:
        raise _usage_error("--tools runs tools mode; --mode agent conflicts with it.")
    if agent and mode is ModeChoice.tools:
        raise _usage_error("--agent runs agent mode; --mode tools conflicts with it.")
    if list_molds:
        if quick:
            raise _usage_error("--list only reads the catalog; --quick applies to --agent.")
        if no_redact:
            raise _usage_error(
                "--list only reads the catalog; --no-redact applies to --tools and --agent."
            )
        if limits:
            raise _usage_error(
                "--list only reads the catalog; limit options apply to --tools and --agent."
            )
        if baseline is not None or no_baseline:
            raise _usage_error(
                "--list only reads the catalog; baseline options apply to --tools and --agent."
            )
        return
    if quick and not agent:
        raise _usage_error("--quick applies only to --agent.")


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
    agent: Annotated[
        bool,
        typer.Option(
            "--agent",
            help="Send the attacks to your agent, which uses its own model and key; 5 "
            "repetitions each. With --list, list the agent molds only.",
        ),
    ] = False,
    quick: Annotated[
        bool,
        typer.Option(
            "--quick",
            help="With --agent: about 15 molds spread over the damages, 1 repetition each.",
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
    baseline: Annotated[
        Path | None,
        typer.Option(
            "--baseline",
            metavar="PATH",
            help="Compare with this baseline; it must exist. Defaults to gazua-baseline.json "
            "when present.",
            show_default=False,
        ),
    ] = None,
    no_baseline: Annotated[
        bool,
        typer.Option("--no-baseline", help="Ignore any baseline: every gated finding fails."),
    ] = False,
) -> None:
    """Run the attacks in tools or agent mode, or list the attack catalog by damage and mode."""
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
    _check_run_options(
        list_molds=list_molds,
        tools=tools,
        agent=agent,
        quick=quick,
        mode=mode,
        no_redact=no_redact,
        limits=limits,
        baseline=baseline,
        no_baseline=no_baseline,
    )
    _refuse_no_redact_in_ci(no_redact)
    if list_molds:
        listed: Literal["tools", "agent"] | None = None
        if tools or mode is ModeChoice.tools:
            listed = "tools"
        elif agent or mode is ModeChoice.agent:
            listed = "agent"
        _list_catalog(config_path, listed, mold, "pt" if language is LanguageChoice.pt else "en")
        return
    path = config_path if config_path is not None else DEFAULT_CONFIG
    choice = BaselineChoice(path=baseline, disabled=no_baseline)
    if agent:
        _run_agent(path, mold, quick, language.value, limits, no_redact, choice)
        return
    if not tools:
        raise _usage_error(RUN_CHOICE_MESSAGE)
    _run_tools(path, mold, language.value, limits, no_redact, choice)


@app.command(name="demo")
def demo_command(
    output: Annotated[
        Path,
        typer.Option(
            "--output",
            metavar="PATH",
            help="Folder of the demo: its configuration, reports and page. Created if missing.",
        ),
    ] = Path("gazua-demo"),
    no_open: Annotated[
        bool,
        typer.Option("--no-open", help="Do not open the demo page in a browser."),
    ] = False,
    language: Annotated[
        LanguageChoice,
        typer.Option("--language", help="Language of the attack text and of the demo notice."),
    ] = LanguageChoice.en,
) -> None:
    """Attack a fictional store assistant run by a scripted model: tools mode, then agent mode.

    Needs no key, configuration or network. The scripted model shows that Gazua works; it does
    not measure how a real model resists.
    """
    from gazua.demo.models import DemoOptions
    from gazua.demo.runner import run_demo
    from gazua.demo.workspace import DemoError

    options = DemoOptions(
        output=str(output),
        no_open=no_open,
        language="pt" if language is LanguageChoice.pt else "en",
    )
    try:
        result = run_demo(options, _report_output())
    except DemoError as error:
        raise _usage_error(error.message) from None
    except KeyboardInterrupt:
        raise _usage_error("Interrupted; the demo stopped before its next mode.") from None
    raise typer.Exit(result.exit_code)


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


DEFAULT_RUN_JSON = Path(".gazua") / "run.json"


def _baseline_error(error: Any) -> typer.Exit:
    from gazua.config.diagnostics import sanitize

    where = f" ({sanitize(error.field)})" if error.field else ""
    return _usage_error(f"{error.code}{where}: {error.message}")


def _project_config(config_path: Path) -> Any:
    from gazua.config.loader import load_config

    if not config_path.is_file():
        raise _usage_error(
            "No configuration at this path. Create one with gazua init, or pass --config."
        )
    with exit_on_config_error():
        return load_config(config_path).config


@app.command(name="baseline")
def baseline_command(
    config_path: Annotated[
        Path,
        typer.Option(
            "--config", metavar="PATH", help="Configuration of the project. Nothing is imported."
        ),
    ] = DEFAULT_CONFIG,
    source: Annotated[
        Path,
        typer.Option(
            "--from",
            metavar="PATH",
            help="The run.json whose findings are accepted. Nothing is executed.",
        ),
    ] = DEFAULT_RUN_JSON,
    output: Annotated[
        Path,
        typer.Option(
            "--output",
            metavar="PATH",
            help="Baseline file inside the project, outside .gazua/. Created or merged.",
        ),
    ] = Path("gazua-baseline.json"),
) -> None:
    """Accept the findings of a saved run as known, in a versionable baseline file.

    Entries the run does not show are kept: nothing is closed by absence. Only gazua verify
    closes a finding.
    """
    from gazua.baseline.storage import BaselineError, accept_report, resolve_baseline_path
    from gazua.reports.execution import installed_version
    from gazua.reports.lifecycle import LifecycleLock, LockBusy
    from gazua.reports.storage import RunLoadError, parse_run_document, read_run_bytes

    _project_config(config_path)
    root = config_path.parent.resolve()
    origin = source if source.is_absolute() else root / source
    try:
        document = parse_run_document(read_run_bytes(origin))
    except RunLoadError as error:
        raise _usage_error(LOAD_MESSAGES.get(error.code, "This run.json cannot be read.")) from None
    lock: Any = LifecycleLock(root)
    try:
        lock.__enter__()
    except LockBusy:
        raise _usage_error(LOCK_BUSY) from None
    except OSError:
        lock = None
    try:
        target = resolve_baseline_path(root, output, config_path=config_path.resolve())
        result = accept_report(target, document, installed_version())
    except BaselineError as error:
        raise _baseline_error(error) from None
    finally:
        if lock is not None:
            lock.__exit__(None, None, None)
    shown = output.as_posix()
    if result.untested:
        _say(
            f"Warning: {result.untested} scenarios of run {document.run_id} were not tested; "
            "the baseline does not certify them.",
            err=True,
        )
    counts = f"{result.accepted} accepted, {result.preserved} preserved, {result.reopened} reopened"
    if not result.changed:
        _say_lines([f"Baseline {shown} unchanged ({counts}, revision {result.revision})."])
        return
    verb = "Created" if result.created else "Updated"
    _say_lines([f"{verb} baseline {shown}: {counts} (revision {result.revision})."])
    _say(
        "Accepted findings stay open: they no longer fail the build, and only gazua verify "
        "closes them."
    )


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
