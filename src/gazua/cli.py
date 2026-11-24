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
    "entrypoint must be a Python test function; declare an HTTP target under http.endpoint "
    "and confirm it with gazua init --http URL (docs/http.md)."
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
    mcp: Annotated[
        str | None,
        typer.Option(
            "--mcp",
            metavar="EXECUTABLE",
            help="Start this MCP stdio server and list its tools with tools/list. It runs the "
            "server's code; no tool is called.",
        ),
    ] = None,
    mcp_arg: Annotated[
        list[str] | None,
        typer.Option(
            "--mcp-arg",
            metavar="ARGUMENT",
            help="One argument of the MCP server, repeatable and kept in order. No shell reads it.",
        ),
    ] = None,
    mcp_cwd: Annotated[
        str | None,
        typer.Option(
            "--mcp-cwd",
            metavar="FOLDER",
            help="Folder the MCP server starts in, relative to the project. Defaults to it.",
        ),
    ] = None,
    http: Annotated[
        str | None,
        typer.Option(
            "--http",
            metavar="URL",
            help="Record an HTTP test endpoint for agent mode and confirm, by typing a phrase, "
            "that you are authorized to send it real requests. No request is sent.",
        ),
    ] = None,
    typescript: Annotated[
        str | None,
        typer.Option(
            "--typescript",
            metavar="MODULE",
            help="Compiled ESM module of a TypeScript test entrypoint, relative to the project. "
            "Node imports it to list the tools wrapped with the npm package; nothing is called.",
        ),
    ] = None,
    typescript_export: Annotated[
        str | None,
        typer.Option(
            "--typescript-export",
            metavar="NAME",
            help="Export of the module that receives each message. Required with --typescript.",
        ),
    ] = None,
    typescript_reset: Annotated[
        str | None,
        typer.Option("--typescript-reset", metavar="NAME", help="Export that resets test state."),
    ] = None,
    typescript_as_user: Annotated[
        str | None,
        typer.Option(
            "--typescript-as-user", metavar="NAME", help="Export that runs a tool as a user."
        ),
    ] = None,
    typescript_output_sink: Annotated[
        str | None,
        typer.Option(
            "--typescript-output-sink",
            metavar="NAME",
            help="Export that shows an output the way your product would.",
        ),
    ] = None,
) -> None:
    """Create gazua.yaml from the tools found in a project, for human review."""
    from gazua.config.diagnostics import sanitize
    from gazua.project_init import check_target, initialize_project, suggests_sensitive

    if mcp is None and (mcp_arg or mcp_cwd is not None):
        raise _usage_error("--mcp-arg and --mcp-cwd describe the server given with --mcp.")
    hooks = {
        "reset_export": typescript_reset,
        "as_user_export": typescript_as_user,
        "output_sink_export": typescript_output_sink,
    }
    if typescript is None and (typescript_export is not None or any(hooks.values())):
        raise _usage_error(
            "The --typescript-* options describe the module given with --typescript."
        )
    if typescript is not None:
        if mcp is not None or entrypoint is not None or http is not None:
            raise _usage_error(
                "--typescript declares the target alone; drop --entrypoint, --mcp and --http."
            )
        if typescript_export is None:
            raise _usage_error("--typescript needs --typescript-export with the entrypoint export.")
        _init_typescript(directory, typescript, typescript_export, hooks)
        return
    if http is not None:
        if mcp is not None or entrypoint is not None:
            raise _usage_error("--http declares the target alone; drop --mcp and --entrypoint.")
        _init_http(directory, http)
        return
    if mcp is not None:
        _init_mcp(directory, mcp, mcp_arg or [], mcp_cwd or ".", entrypoint)
        return
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


def _init_typescript(
    directory: Path, module: str, export: str, hooks: dict[str, str | None]
) -> None:
    from pydantic import ValidationError

    from gazua.config.diagnostics import sanitize
    from gazua.config.models import TypeScriptTarget
    from gazua.project_init import check_target, initialize_typescript_project, suggests_sensitive

    try:
        target = TypeScriptTarget(
            module=module,
            entrypoint_export=export,
            **{name: value for name, value in hooks.items() if value is not None},
        )
    except ValidationError:
        raise _usage_error(
            "--typescript needs a relative .js or .mjs path inside the project, and every "
            "export must be a JavaScript identifier."
        ) from None
    with exit_on_config_error():
        check_target(directory)
        _say(
            f"Warning: listing tools imports {sanitize(module)} in Node on this machine with your "
            "permissions. Gazua does not install packages or build TypeScript.",
            err=True,
        )
        result = initialize_typescript_project(directory, target)
    if result.tools:
        _say("Discovered TypeScript tools (suggestions, review required):")
        for name in result.tools:
            suggestion = "sensitive" if suggests_sensitive(name) else "not classified"
            _say(f"  {sanitize(name)}: {suggestion}, dry-run until reviewed")
    else:
        _say("The module registered no tool through wrap or tool.")
    for name in result.ambiguous:
        _say(f"Warning: distinct functions share the tool name {sanitize(name)}.", err=True)
    for warning in result.warnings:
        _say(f"Warning: {warning.render()}", err=True)
    _say(f"Created {sanitize(str(result.config_path))}")
    if result.gitignore_changed:
        _say(f"Added .gazua/ to {sanitize(str(result.gitignore_path))}")
    else:
        _say(f"{sanitize(str(result.gitignore_path))} already ignores .gazua/")
    _say(
        "The entrypoint and the tools were not called. Review the file, then run gazua run --agent."
    )


def _init_mcp(
    directory: Path, command: str, arguments: list[str], cwd: str, entrypoint: str | None
) -> None:
    from pydantic import ValidationError

    from gazua.config.diagnostics import sanitize
    from gazua.config.models import McpServer
    from gazua.mcp import EXTRA_MISSING_MESSAGE, extra_available
    from gazua.mcp.models import McpLaunch
    from gazua.project_init import check_target, initialize_mcp_project, suggests_sensitive

    try:
        server = McpServer(transport="stdio", command=command, args=arguments, cwd=cwd)
    except ValidationError:
        raise _usage_error(
            "The MCP command, its arguments and folder must be non-empty text without NUL."
        ) from None
    if not extra_available():
        raise _usage_error(EXTRA_MISSING_MESSAGE)
    display = McpLaunch(command, tuple(arguments), directory).display
    with exit_on_config_error():
        check_target(directory)
        _say(
            f"Warning: listing MCP tools starts {sanitize(display)} on this machine with your "
            "permissions. Only point --mcp at a test server you trust.",
            err=True,
        )
        result = initialize_mcp_project(directory, server, entrypoint)
    tools = result.inventory.tools
    if tools:
        _say("Discovered MCP tools (suggestions, review required):")
        for tool in tools:
            suggestion = "sensitive" if suggests_sensitive(tool.name) else "not classified"
            _say(f"  {sanitize(tool.name)}: {suggestion}, dry-run until reviewed")
    else:
        _say("The MCP server listed no tools.")
    for warning in result.warnings:
        _say(f"Warning: {warning.render()}", err=True)
    _say(f"Created {sanitize(str(result.config_path))}")
    if result.gitignore_changed:
        _say(f"Added .gazua/ to {sanitize(str(result.gitignore_path))}")
    else:
        _say(f"{sanitize(str(result.gitignore_path))} already ignores .gazua/")
    _say("Tools were listed with tools/list; none was called. Annotations grant nothing.")
    _say(
        "Every tool stays in dry-run until you mark it safe: true for test data and give it a "
        "class. Then run gazua run --tools."
    )
    _say("Review every REVIEW REQUIRED comment before relying on this file.")


def _interactive() -> bool:
    """A confirmation needs a person at a terminal; piped or redirected input never confirms."""
    return sys.stdin.isatty()


def _init_http(directory: Path, endpoint: str) -> None:
    from gazua.config.diagnostics import sanitize
    from gazua.http.models import parse_endpoint
    from gazua.project_init import authorization_phrase, initialize_http_project, prepare_http_init

    with exit_on_config_error():
        prepare_http_init(directory, endpoint)
    parsed = parse_endpoint(endpoint)
    phrase = authorization_phrase(parsed.origin)
    _say(f"Origin: {sanitize(parsed.origin)}")
    _say(f"Path: {sanitize(parsed.target)}")
    _say(
        "Warning: HTTP has no dry-run. Every attack is a real POST to this endpoint, and the "
        "tools behind it run for real. Use a test environment with synthetic data only.",
        err=True,
    )
    if not _interactive():
        raise _usage_error(
            "The authorization must be typed at an interactive terminal; nothing was written."
        )
    _say(f"Type exactly: {sanitize(phrase)}")
    try:
        typed = input("> ")
    except (EOFError, KeyboardInterrupt):
        typed = ""
    if typed.strip() != phrase:
        raise _usage_error("The phrase did not match; nothing was written.")
    with exit_on_config_error():
        result = initialize_http_project(directory, endpoint, confirmed=True)
    for warning in result.warnings:
        _say(f"Warning: {warning.render()}", err=True)
    if result.created_config:
        _say(f"Created {sanitize(str(result.config_path))}")
    else:
        _say(f"Kept {sanitize(str(result.config_path))}")
    if result.gitignore_path is not None:
        if result.gitignore_changed:
            _say(f"Added .gazua/ to {sanitize(str(result.gitignore_path))}")
        else:
            _say(f"{sanitize(str(result.gitignore_path))} already ignores .gazua/")
    _say(f"Recorded the authorization in {sanitize(str(result.receipt_path))}")
    _say("No request was sent. Declare the target's tools, then run gazua run --agent.")


HTTP_PROVENANCE_WARNING = (
    "This finding was not recorded over HTTP against this origin, or that run is no longer "
    "kept. This verification cannot close it; run gazua run --agent again and review the "
    "baseline."
)
TYPESCRIPT_PROVENANCE_WARNING = (
    "The TypeScript module or the npm package differs from the run that recorded this finding, "
    "or that run is no longer kept. This verification cannot close it; run gazua run --agent "
    "again and review the baseline."
)
MCP_PROVENANCE_WARNING = (
    "The MCP server's tools differ from the run that recorded this finding, or that run is no "
    "longer kept. This verification cannot close it; run gazua run again and review the "
    "baseline."
)


def agent_release(config: Any) -> Literal["v0.2", "v0.4"]:
    """The catalog release agent mode reads: MCP targets also get the description molds."""
    return "v0.4" if config is not None and config.mcp is not None else "v0.2"


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
        # Agent molds arrive with v0.2, and MCP description molds with v0.4; the tools
        # listing keeps its own release.
        release=agent_release(config) if mode == "agent" else None,
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
        "1 to 5, so it needs a migration."
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
    if config.http is not None:
        from gazua.modes.tools import HTTP_REFUSAL

        raise _usage_error(HTTP_REFUSAL)
    if config.typescript is not None:
        from gazua.modes.tools import TYPESCRIPT_REFUSAL

        raise _usage_error(TYPESCRIPT_REFUSAL)
    if config.entrypoint is None and config.mcp is None:
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
        release=agent_release(config),
    )
    if catalog.has_errors:
        for diagnostic in catalog.diagnostics:
            _say(diagnostic.render(), err=True)
        raise typer.Exit(EXIT_USAGE)
    with exit_on_config_error():
        select_agent_molds(catalog.entries, AgentOptions(mold=mold, quick=quick))
    if config.entrypoint is None and config.http is None and config.typescript is None:
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


@app.command(name="mcp-proxy")
def mcp_proxy_command() -> None:
    """Stdio MCP server for a test agent's client, during a Gazua agent run only.

    It connects to the run's broker, which applies dry-run and delivers the attack texts. It
    takes no server command or policy: outside a run it exits with code 2.
    """
    from gazua.mcp.proxy import run_proxy

    raise typer.Exit(run_proxy())


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


def _verify_error(error: Any) -> typer.Exit:
    lines = [f"{error.code}: {error.message}"]
    lines.extend(f"  {item}" for item in error.choices)
    _say_lines(lines, err=True)
    return typer.Exit(EXIT_USAGE)


@app.command(name="verify")
def verify_command(
    finding: Annotated[
        str,
        typer.Argument(
            metavar="FINDING",
            help="A full finding id, or the exact mold id of one accepted finding.",
        ),
    ],
    config_path: Annotated[
        Path,
        typer.Option("--config", metavar="PATH", help="Configuration of the project."),
    ] = DEFAULT_CONFIG,
    baseline_path: Annotated[
        Path,
        typer.Option("--baseline", metavar="PATH", help="Baseline file; it must exist."),
    ] = Path("gazua-baseline.json"),
    mode: Annotated[
        ModeChoice | None,
        typer.Option("--mode", help="Only findings of this mode.", show_default=False),
    ] = None,
    max_runs: Annotated[
        int | None,
        typer.Option("--max-runs", min=1, help="Most executions to start.", show_default=False),
    ] = None,
    timeout: Annotated[
        float | None,
        typer.Option("--timeout", help="Seconds per execution.", show_default=False),
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
        typer.Option("--max-cost", help="Cost ceiling in USD.", show_default=False),
    ] = None,
) -> None:
    """Run an accepted finding's attack 20 times per scenario to check a fix.

    Only 0 successes in 20 for every scenario closes it (up to ~14% at 95% confidence); any
    success keeps it open. A normal run never closes a finding, and an interrupted verification
    changes nothing.
    """
    from pydantic import ValidationError

    from gazua.baseline.plan import build_plan, check_budget, preview_lines
    from gazua.baseline.presentation import verification_lines
    from gazua.baseline.selection import VerifyError, resolve
    from gazua.baseline.storage import BaselineError, read_baseline, resolve_baseline_path
    from gazua.baseline.verification import run_verification
    from gazua.catalog.loader import load_catalog
    from gazua.config.diagnostics import ConfigError
    from gazua.modes.tools import discover_tools
    from gazua.reports.execution import installed_version
    from gazua.reports.lifecycle import LifecycleLock, LockBusy, gitignore_covers
    from gazua.runtime.engine import effective_limits
    from gazua.runtime.run_models import LimitOverrides

    limits = {
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
    try:
        overrides = LimitOverrides.model_validate(limits)
    except ValidationError:
        raise _usage_error("Limit options must be positive numbers.") from None
    config = _load_tools_config(config_path, AGENT_HTTP_REFUSAL)
    if (
        config.entrypoint is None
        and config.mcp is None
        and config.http is None
        and config.typescript is None
    ):
        raise _usage_error("Verification runs the target; declare entrypoint.")
    root = config_path.parent.resolve()
    try:
        path = resolve_baseline_path(root, baseline_path, config_path=config_path.resolve())
    except BaselineError as error:
        raise _baseline_error(error) from None
    catalog = load_catalog(
        config,
        config_dir=config_path.parent,
        on_warning=lambda warning: _say(warning.message, err=True),
        release=agent_release(config),
    )
    if catalog.has_errors:
        for diagnostic in catalog.diagnostics:
            _say(diagnostic.render(), err=True)
        raise typer.Exit(EXIT_USAGE)
    if not gitignore_covers(root):
        _say(GITIGNORE_WARNING, err=True)
    lock: Any = LifecycleLock(root)
    try:
        lock.__enter__()
    except LockBusy:
        raise _usage_error(LOCK_BUSY) from None
    except OSError:
        lock = None
    try:
        try:
            loaded = read_baseline(path)
        except BaselineError as error:
            raise _baseline_error(error) from None
        chosen_mode: Literal["tools", "agent"] | None = None if mode is None else mode.value
        try:
            selection = resolve(finding, loaded.document, config, catalog.entries, chosen_mode)
        except VerifyError as error:
            raise _verify_error(error) from None
        chosen = effective_limits(config, overrides)
        try:
            extra: list[str] = []
            with exit_on_config_error():
                if config.http is not None:
                    from gazua.baseline.verification import http_provenance_problem
                    from gazua.http.policy import check_run
                    from gazua.modes.agent import http_inventory

                    # A replay sends real requests, so it needs the current authorization.
                    origin = check_run(config, root).origin
                    inventory = http_inventory(config)
                    problem = http_provenance_problem(root, selection.entry.id, origin)
                    if problem is not None:
                        extra.append(problem)
                        _say(HTTP_PROVENANCE_WARNING, err=True)
                else:
                    inventory = discover_tools(config, root, timeout=chosen.timeout)
                    if selection.mode == "agent":
                        from gazua.modes.agent import check_entries

                        check_entries(config, inventory)
            plan = build_plan(selection, config, inventory)
            check_budget(plan, chosen)
            if config.mcp is not None:
                from gazua.baseline.verification import mcp_provenance_problem

                problem = mcp_provenance_problem(root, selection.entry.id, inventory)
                if problem is not None:
                    extra.append(problem)
                    _say(MCP_PROVENANCE_WARNING, err=True)
            if config.typescript is not None:
                from gazua.baseline.verification import typescript_provenance_problem

                problem = typescript_provenance_problem(root, selection.entry.id, inventory)
                if problem is not None:
                    extra.append(problem)
                    _say(TYPESCRIPT_PROVENANCE_WARNING, err=True)
        except VerifyError as error:
            raise _verify_error(error) from None
        except ConfigError:
            raise typer.Exit(EXIT_USAGE) from None

        def show_preview(run_plan: Any) -> None:
            _say_lines(
                preview_lines(
                    plan, run_plan.limits, effective_concurrency=run_plan.effective_concurrency
                )
            )

        with exit_on_config_error():
            outcome = run_verification(
                plan,
                config,
                overrides,
                root,
                loaded,
                _report_output(),
                locked=lock is not None,
                config_path=config_path.name,
                gazua_version=installed_version(),
                show_preview=show_preview,
                inventory=inventory,
                extra_failures=extra,
            )
    finally:
        if lock is not None:
            lock.__exit__(None, None, None)
    if outcome.result is not None:
        if outcome.persisted is False:
            reason = (outcome.error or "report").replace("_", " ")
            _say(f"The baseline was not changed ({reason}).", err=True)
        _say_lines(
            verification_lines(
                outcome.result, selection.mode, persisted=outcome.persisted is not False
            )[-1:]
        )
    raise typer.Exit(outcome.exit_code)


ISSUE_MESSAGES = {
    "issues_unredacted_source": (
        "This run.json was captured with --no-redact; issues are only exported from masked "
        "runs. Run gazua run again without --no-redact."
    ),
    "issues_path_refused": (
        ".gazua/issues/ or the run's folder in it is a link or not a plain directory; it was "
        "left as it is."
    ),
    "issues_conflict": (
        "This run's issues were already exported with other content or options. Pass "
        "--overwrite to replace that export; manual edits in its files will be lost."
    ),
    "issues_unmanaged_destination": (
        "The run's folder in .gazua/issues/ was not written by Gazua or holds other files; it "
        "was left as it is. Move it away to export again."
    ),
    "issues_write_failed": (
        "The issues could not be written to .gazua/issues/; the previous export was kept."
    ),
    "issues_recovery_failed": (
        "An interrupted export in .gazua/issues/ could not be rolled back; check the folder's "
        "permissions and run gazua issues again."
    ),
}


@app.command(name="issues")
def issues_command(
    source: Annotated[
        str,
        typer.Option(
            "--from",
            metavar="PATH",
            help="The local run.json whose findings become issues. Nothing is executed.",
        ),
    ] = DEFAULT_RUN_JSON.as_posix(),
    include_attack: Annotated[
        bool,
        typer.Option(
            "--include-attack",
            help="Also copy each scenario's attack text and payload, still masked.",
        ),
    ] = False,
    overwrite: Annotated[
        bool,
        typer.Option(
            "--overwrite",
            help="Replace this run's previous export, even if its files were edited.",
        ),
    ] = False,
) -> None:
    """Write one Markdown issue per finding to .gazua/issues/<run-id>/, offline.

    Each file has the finding id, the fix guide, the confirmation command and the acceptance
    criteria, ready to copy into a backlog. Nothing is sent to any service.
    """
    from gazua.issues.export import export_issues
    from gazua.issues.models import IssueExportError, IssueOptions
    from gazua.reports.lifecycle import LockBusy
    from gazua.reports.storage import RunLoadError, StorageError

    if "://" in source:
        raise _usage_error("--from takes a local run.json path, not a URL.")
    options = IssueOptions(Path(source), include_attack=include_attack, overwrite=overwrite)
    try:
        result = export_issues(Path.cwd(), options)
    except RunLoadError as error:
        raise _usage_error(LOAD_MESSAGES.get(error.code, "This run.json cannot be read.")) from None
    except IssueExportError as error:
        raise _usage_error(
            ISSUE_MESSAGES.get(error.code, "The issues could not be exported.")
        ) from None
    except LockBusy:
        raise _usage_error(LOCK_BUSY) from None
    except (StorageError, OSError):
        raise _usage_error(ISSUE_MESSAGES["issues_write_failed"]) from None
    except KeyboardInterrupt:
        _say("Interrupted; no partial export was published.", err=True)
        raise typer.Exit(130) from None
    if result.status == "empty":
        _say_lines([f"Run {result.run_id} has no finding; 0 issue files written."])
        return
    noun = "issue file" if result.count == 1 else "issue files"
    if result.status == "unchanged":
        _say_lines([f"{result.count} {noun} already up to date in {result.directory}/."])
    else:
        _say_lines([f"Wrote {result.count} {noun} to {result.directory}/."])
    if include_attack:
        _say(
            "Warning: these issues include attack text and payloads. Masking only recognizes "
            "known formats; review them before sharing.",
            err=True,
        )
    _say("Copy them into your backlog by hand; Gazua never opens issues on any service.")


@app.command(name="clean")
def clean_command() -> None:
    """Remove Gazua's runs, reports, evidence and issue exports from ./.gazua.

    Unknown files stay.
    """
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
    if result.issue_exports:
        _say(f"Removed {result.issue_exports} issue exports.")
    if result.pending:
        _say("Could not remove these, check their permissions:", err=True)
        _say_lines([f"  {item}" for item in result.pending], err=True)
        raise typer.Exit(2)


def main() -> int:
    app(prog_name="gazua")
    return 0
