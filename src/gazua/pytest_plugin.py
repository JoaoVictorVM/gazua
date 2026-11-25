"""pytest-gazua: runs selected tools molds as tests, with the same verdicts as the CLI.

Installing Gazua registers this plugin, but nothing is read or run without ``--gazua``. Each
selected mold becomes one item, ``gazua::<mold-id>``, that runs tools mode through the same
services as ``gazua run --tools`` and maps the effective result to a pytest state:

- a new gated finding fails;
- a known finding, or a new one that is not gated, is xfailed (not strict);
- a mold whose scenarios resisted passes;
- a mold that was not tested, or did not apply, is skipped;
- an operational, configuration or storage error is an error.

The plugin never judges again: severity, state, baseline and gate are the run's. It covers
tools mode only and refuses pytest-xdist with more than one worker.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final

import pytest

from gazua.pytest_models import ITEM_PREFIX, GazuaOptions, MoldResult, describe

XDIST_REFUSAL: Final = (
    "pytest_gazua_xdist_unsupported: Gazua items cannot run with pytest-xdist workers; "
    "run them with -n0."
)
_STATE: Final = pytest.StashKey["_Session"]()


class GazuaRunError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("gazua", "Gazua security tests (tools mode)")
    group.addoption(
        "--gazua",
        action="store_true",
        default=False,
        help="Add one test per selected Gazua tools mold. Off by default.",
    )
    group.addoption(
        "--gazua-config",
        default="gazua.yaml",
        metavar="PATH",
        help="Gazua configuration, as gazua run --config. Default: gazua.yaml.",
    )
    group.addoption(
        "--gazua-mold",
        action="append",
        default=[],
        metavar="ID",
        help="Run this tools mold, by exact id. Repeat it for more; default: all tools molds.",
    )
    group.addoption(
        "--gazua-baseline",
        default=None,
        metavar="PATH",
        help="Compare with this baseline; default: gazua-baseline.json when present.",
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "gazua: a Gazua tools mold run as a test")


def options_of(config: pytest.Config) -> GazuaOptions:
    base = Path(config.invocation_params.dir)
    baseline = config.getoption("gazua_baseline")
    return GazuaOptions(
        enabled=bool(config.getoption("gazua")),
        config=base / str(config.getoption("gazua_config")),
        molds=tuple(str(item) for item in config.getoption("gazua_mold") or ()),
        baseline=None if baseline is None else Path(str(baseline)),
    )


def refuse_xdist(config: pytest.Config) -> None:
    """Workers would run molds concurrently in one ``.gazua``; the result must stay exact."""
    if hasattr(config, "workerinput"):
        raise pytest.UsageError(XDIST_REFUSAL)
    workers: Any = getattr(config.option, "numprocesses", None)
    if workers not in (None, 0, 1, "0", "1"):
        raise pytest.UsageError(XDIST_REFUSAL)


def _usage(diagnostics: Any) -> pytest.UsageError:
    lines = [item.render() for item in diagnostics]
    return pytest.UsageError("\n".join(lines) or "Gazua configuration error.")


class _Session:
    """The configuration, catalog and baseline of this pytest session, read once."""

    def __init__(self, options: GazuaOptions) -> None:
        from gazua.catalog.loader import load_catalog
        from gazua.config.diagnostics import ConfigError
        from gazua.config.loader import load_config
        from gazua.modes.tools import HTTP_REFUSAL, TYPESCRIPT_REFUSAL, tools_molds

        path = options.config
        if not path.is_file():
            raise pytest.UsageError(
                "No Gazua configuration at --gazua-config. Create one with gazua init."
            )
        try:
            self.config: Any = load_config(path).config
        except ConfigError as error:
            raise _usage(error.diagnostics) from None
        if self.config.http is not None:
            raise pytest.UsageError(HTTP_REFUSAL)
        if self.config.typescript is not None:
            raise pytest.UsageError(TYPESCRIPT_REFUSAL)
        if self.config.entrypoint is None and self.config.mcp is None:
            raise pytest.UsageError(
                "Tools mode imports the entrypoint's module to find the tools; declare entrypoint."
            )
        catalog = load_catalog(self.config, config_dir=path.parent)
        if catalog.has_errors:
            raise _usage(catalog.diagnostics)
        self.entries: Any = catalog.entries
        try:
            every = tools_molds(self.entries)
            for mold_id in options.selected():
                tools_molds(self.entries, mold_id)
        except ConfigError as error:
            raise _usage(error.diagnostics) from None
        chosen = set(options.selected())
        self.molds = [mold.id for mold in every if not chosen or mold.id in chosen]
        self.root = path.parent.resolve()
        self.config_name = path.name
        self.baseline_path = options.baseline
        self._baseline: Any = None
        self._baseline_read = False

    def baseline(self) -> Any:
        """Read once, as ``gazua run`` reads it: an explicit file must exist and parse."""
        from gazua.baseline.models import BASELINE_FILE
        from gazua.baseline.storage import BaselineError, read_baseline, resolve_baseline_path

        if self._baseline_read:
            return self._baseline
        chosen = self.baseline_path
        try:
            path = resolve_baseline_path(
                self.root,
                chosen if chosen is not None else Path(BASELINE_FILE),
                config_path=(self.root / self.config_name),
            )
            self._baseline = read_baseline(path)
        except BaselineError as error:
            if not (error.code == "baseline_missing" and chosen is None):
                raise GazuaRunError(error.code) from None
            self._baseline = None
        self._baseline_read = True
        return self._baseline

    def run(self, mold_id: str) -> MoldResult:
        from gazua.ci.projection import ProjectionError, project
        from gazua.config.diagnostics import ConfigError
        from gazua.modes.tools_models import ToolsOptions
        from gazua.reports.execution import ReportOutput, execute_mode
        from gazua.reports.lifecycle import LifecycleLock, LockBusy
        from gazua.runtime.run_models import LimitOverrides

        baseline = self.baseline()
        options = ToolsOptions(
            mold=mold_id, language="en", overrides=LimitOverrides(), config_path=self.config_name
        )
        lines: list[str] = []
        output = ReportOutput(say=lines.append, lines=lines.extend, warn=lines.append)
        try:
            with LifecycleLock(self.root):
                outcome = execute_mode(
                    "tools",
                    self.config,
                    self.entries,
                    options,
                    self.root,
                    output,
                    locked=True,
                    baseline=baseline,
                )
        except LockBusy:
            raise GazuaRunError("lifecycle_lock_busy") from None
        except ConfigError as error:
            raise GazuaRunError(
                error.diagnostics[0].code if error.diagnostics else "config"
            ) from None
        except OSError:
            raise GazuaRunError("storage_unavailable") from None
        document = outcome.document
        if outcome.interrupted or (document is not None and document.engine.interrupted):
            raise KeyboardInterrupt
        if document is None or outcome.exit_code == 2:
            errors = [] if document is None else list(document.verdicts.operational_errors)
            raise GazuaRunError(errors[0] if errors else "operational_error")
        try:
            summary = project(document)
        except ProjectionError as error:
            raise GazuaRunError(error.code) from None
        states = [item.state for item in document.verdicts.results]
        return MoldResult(
            mold_id=mold_id,
            run_id=document.run_id,
            exit_code=outcome.exit_code,
            findings=tuple(summary.findings),
            resisted=states.count("resisted"),
            not_tested=states.count("not_tested") + states.count("conditional_risk"),
            not_applicable=states.count("not_applicable"),
        )


class GazuaItem(pytest.Item):
    """One tools mold. Setup runs it; the call maps its result without judging again."""

    def __init__(self, *, mold_id: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)  # pyright: ignore[reportUnknownMemberType]
        self.mold_id = mold_id
        self.result: MoldResult | None = None
        self.add_marker("gazua")

    def setup(self) -> None:
        state = self.config.stash[_STATE]
        try:
            self.result = state.run(self.mold_id)
        except GazuaRunError as error:
            pytest.fail(f"Gazua {error.code}: the mold could not run; see .gazua/.", pytrace=False)

    def runtest(self) -> None:
        result = self.result
        if result is None:
            pytest.fail("Gazua: the mold did not run.", pytrace=False)
        state, code = result.state()
        if state == "failed":
            pytest.fail(describe(result, result.gated), pytrace=False)
        if state == "xfailed":
            pytest.xfail(f"{code}: {describe(result, result.findings)}")
        if state == "skipped":
            pytest.skip(code)

    def reportinfo(self) -> tuple[Any, int | None, str]:
        return self.path, None, f"{ITEM_PREFIX}{self.mold_id}"


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(
    session: pytest.Session, config: pytest.Config, items: list[pytest.Item]
) -> None:
    options = options_of(config)
    if not options.enabled:
        return
    refuse_xdist(config)
    state = _Session(options)
    config.stash[_STATE] = state
    for mold_id in state.molds:
        items.append(
            GazuaItem.from_parent(  # pyright: ignore[reportUnknownMemberType]
                session, name=mold_id, nodeid=f"{ITEM_PREFIX}{mold_id}", mold_id=mold_id
            )
        )
