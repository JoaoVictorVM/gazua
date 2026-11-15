"""Coordinates the demo: workspace, tools mode, agent mode, the index and the browser.

Both modes run through the same service as ``gazua run``, with the native engines, verdicts
and reports; the demo computes no verdict of its own. A gated finding does not stop the
sequence, since findings are what the demo is for. An operational error, a failure to save the
reports or an interruption stops it before the next mode. Exit codes follow the modes' gate:
2 wins over 1, which wins over 0.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Final

from gazua.demo import MODEL_ID, TARGET_VERSION
from gazua.demo.models import (
    BrowserOutcome,
    DemoMode,
    DemoOptions,
    DemoResult,
    ExitCode,
    ModeOutcome,
)
from gazua.demo.presentation import Opener, notice, open_index, write_index
from gazua.demo.workspace import RESOURCE, DemoError, Workspace, prepare_workspace
from gazua.reports.execution import ExecutionOutcome, ReportOutput

LOCK_BUSY: Final = (
    "Another Gazua command is using .gazua/ in this folder. Try again when it finishes."
)
INDEX_FAILED: Final = "The demo page could not be written; the reports above were kept."
BROWSER_FAILED: Final = "Could not open a browser. Open this file to see the reports: {path}"
HEADINGS: Final[dict[DemoMode, str]] = {
    "tools": "Demo, part 1 of 2: tools mode calls the store's tools directly, with no model.",
    "agent": (
        "Demo, part 2 of 2: agent mode sends the attacks to the store assistant, "
        f"run by the scripted model {MODEL_ID}, 5 repetitions each."
    ),
}


def exit_precedence(*codes: ExitCode | None) -> ExitCode:
    """2 over 1 over 0; a mode that did not run adds nothing."""
    found: list[ExitCode] = [code for code in codes if code is not None]
    return max(found) if found else 2


def _not_started(mode: DemoMode, reason: str) -> ModeOutcome:
    return ModeOutcome(mode=mode, started=False, exit_code=None, reason=reason)


def _outcome(mode: DemoMode, root: Path, executed: ExecutionOutcome) -> ModeOutcome:
    document = executed.document
    reports: dict[str, Path] = {}
    archive: Path | None = None
    if "archive" in executed.paths and document is not None:
        archive = root / executed.paths["archive"]
        folder = archive.parent
        reports = {
            "html": folder / "report.html",
            "markdown": folder / "report.md",
            "json": archive,
        }
    reason = None
    if executed.interrupted:
        reason = "interrupted"
    elif document is None:
        reason = "no_report"
    return ModeOutcome(
        mode=mode,
        started=not executed.interrupted,
        exit_code=executed.exit_code,
        run_id=None if document is None else document.run_id,
        archive=archive,
        reports=reports,
        findings=0 if document is None else len(document.findings),
        native=executed.native,
        reason=reason,
    )


def _load(workspace: Workspace, output: ReportOutput) -> tuple[Any, Any]:
    from gazua.catalog.loader import load_catalog
    from gazua.config.diagnostics import ConfigError
    from gazua.config.loader import load_config

    try:
        config = load_config(workspace.config_path).config
    except ConfigError:
        raise DemoError(RESOURCE) from None
    catalog = load_catalog(
        config,
        config_dir=workspace.root,
        on_warning=lambda warning: output.warn(warning.message),
        # The demo runs the v0.2 catalog in both modes; later molds are not part of it.
        release="v0.2",
    )
    if catalog.has_errors or config.entrypoint is None:
        raise DemoError(RESOURCE)
    return config, catalog.entries


def _run_mode(
    mode: DemoMode,
    config: Any,
    entries: Any,
    options: DemoOptions,
    workspace: Workspace,
    output: ReportOutput,
    locked: bool,
    cancel: threading.Event | None = None,
) -> ModeOutcome:
    from gazua.config.diagnostics import ConfigError
    from gazua.modes.agent_models import AgentOptions
    from gazua.modes.tools_models import ToolsOptions
    from gazua.reports.execution import execute_mode

    output.say(HEADINGS[mode])
    mode_options: Any = (
        ToolsOptions(language=options.language)
        if mode == "tools"
        else AgentOptions(language=options.language)
    )
    try:
        executed = execute_mode(
            mode,
            config,
            entries,
            mode_options,
            workspace.root,
            output,
            locked=locked,
            model=MODEL_ID if mode == "agent" else None,
            target_version=TARGET_VERSION,
            cancel=cancel,
        )
    except ConfigError as error:
        for diagnostic in error.diagnostics:
            output.warn(diagnostic.render())
        return ModeOutcome(mode=mode, started=True, exit_code=2, reason="configuration_error")
    except KeyboardInterrupt:
        return ModeOutcome(mode=mode, started=True, exit_code=2, reason="interrupted")
    return _outcome(mode, workspace.root, executed)


def _stopped(outcome: ModeOutcome) -> bool:
    return outcome.exit_code == 2 or outcome.reason == "interrupted"


def _interrupted(outcome: ModeOutcome) -> bool:
    if outcome.reason == "interrupted":
        return True
    native = outcome.native
    engine = getattr(native, "engine", None)
    return bool(getattr(engine, "interrupted", False))


def run_demo(
    options: DemoOptions,
    output: ReportOutput,
    *,
    opener: Opener | None = None,
    cwd: Path | None = None,
    cancel: threading.Event | None = None,
) -> DemoResult:
    """Runs the whole demo. A workspace or resource problem raises ``DemoError`` first."""
    from gazua.reports.lifecycle import LifecycleLock, LockBusy

    base = cwd if cwd is not None else Path.cwd()
    workspace = prepare_workspace(base / options.output)
    config, entries = _load(workspace, output)
    output.say(notice(options.language))
    output.say(f"Demo folder: {workspace.root}")
    lock: LifecycleLock | None = LifecycleLock(workspace.root)
    try:
        lock.__enter__()  # type: ignore[union-attr]
    except LockBusy:
        output.warn(LOCK_BUSY)
        busy = _not_started("tools", "lock_busy")
        return DemoResult(
            workspace=workspace.root,
            index=None,
            tools=busy,
            agent=_not_started("agent", "lock_busy"),
            browser="not_reached",
            exit_code=2,
        )
    except OSError:
        lock = None
    try:
        locked = lock is not None
        tools = _run_mode("tools", config, entries, options, workspace, output, locked, cancel)
        if _stopped(tools):
            reason = "interrupted" if _interrupted(tools) else "previous_mode_failed"
            agent = _not_started("agent", reason)
        else:
            agent = _run_mode("agent", config, entries, options, workspace, output, locked, cancel)
        code = exit_precedence(tools.exit_code, agent.exit_code)
        index: Path | None = None
        try:
            index = write_index(workspace.root, tools, agent, options.language)
        except OSError:
            output.warn(INDEX_FAILED)
            code = 2
    finally:
        if lock is not None:
            lock.__exit__(None, None, None)
    if not tools.reports and not agent.reports:
        code = 2
    interrupted = _interrupted(tools) or _interrupted(agent)
    browser: BrowserOutcome = "skipped"
    if index is not None:
        output.say(f"Demo page: {index}")
        if not options.no_open and not interrupted:
            browser = open_index(index, opener)
            if browser == "failed":
                output.warn(BROWSER_FAILED.format(path=index))
    else:
        browser = "not_reached"
    output.say(
        f"Tools mode exit code: {_code_text(tools)}. Agent mode exit code: {_code_text(agent)}. "
        f"Demo exit code: {code}."
    )
    output.say(f"Reproduce a finding from {workspace.root}: its commands use the gazua.yaml there.")
    return DemoResult(
        workspace=workspace.root,
        index=index,
        tools=tools,
        agent=agent,
        browser=browser,
        exit_code=code,
    )


def _code_text(outcome: ModeOutcome) -> str:
    if not outcome.started or outcome.exit_code is None:
        return f"not started ({(outcome.reason or 'not_started').replace('_', ' ')})"
    return str(outcome.exit_code)


__all__ = ["HEADINGS", "LOCK_BUSY", "exit_precedence", "run_demo"]
