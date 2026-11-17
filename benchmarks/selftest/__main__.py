"""The contributors' command: one run of the self-test benchmark, with no key.

    uv run --frozen python -m benchmarks.selftest --profile release

Exit codes: 0 every selected cell conforms; 1 a mismatch, an unexpected finding, a leak or a
broken control; 2 an invalid matrix or option, a pending dependency, an interruption or a
result that could not be saved. Findings the vulnerable target is expected to have are part of
a passing result: the benchmark measures conformance, not the absence of findings.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
from collections.abc import Sequence
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Final

from .coverage import MatrixError
from .metrics import controls, detection, false_alarms
from .models import BenchmarkSummary
from .publishing import summary_markdown
from .runner import REPORT_FILE, ROOT, SUMMARY_FILE, BenchmarkOptions, OptionsError, run_benchmark
from .storage import StorageError, write_atomic

REAL_DEFAULT_RUNS: Final = 20
REAL_UNAVAILABLE: Final = (
    "The real-model profile passed its preflight, but running it is not part of this version; "
    "nothing was started."
)


def _decimal(text: str) -> Decimal:
    try:
        value = Decimal(text)
    except InvalidOperation:
        raise argparse.ArgumentTypeError("not a decimal number") from None
    if not value.is_finite() or value <= 0:
        raise argparse.ArgumentTypeError("must be a positive amount")
    return value


def _positive(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("not an integer") from None
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        prog="python -m benchmarks.selftest",
        description="Run Gazua's self-test benchmark against its synthetic targets.",
    )
    command.add_argument("--profile", choices=("release", "full", "real"), default="release")
    command.add_argument("--release", choices=("v0.1", "v0.2", "v0.4"))
    command.add_argument("--framework", action="append", default=[], dest="frameworks")
    command.add_argument("--mold", action="append", default=[], dest="molds")
    command.add_argument("--output", type=Path)
    command.add_argument("--max-cost", type=_decimal)
    command.add_argument("--max-runs", type=_positive)
    command.add_argument("--real-config", type=Path)
    return command


def real_preflight(arguments: Any, environment: dict[str, str]) -> list[str]:
    """Why a real-model run cannot start. It never starts implicitly or in CI."""
    problems: list[str] = []
    if environment.get("CI", "").lower() in ("1", "true", "yes"):
        problems.append("The real-model profile never runs in CI.")
    if arguments.max_cost is None:
        problems.append("--max-cost is required: a positive budget in USD.")
    if arguments.real_config is None:
        problems.append("--real-config is required: the configuration of the real target.")
    elif not arguments.real_config.is_file():
        problems.append("--real-config must name an existing file.")
    else:
        problems.extend(_cost_problems(arguments.real_config))
    return problems


def _cost_problems(path: Path) -> list[str]:
    from gazua.config.diagnostics import ConfigError
    from gazua.config.loader import load_config

    try:
        limits = load_config(path).config.limits
    except ConfigError:
        return ["--real-config is not a valid Gazua configuration."]
    # Zero is not proof that a real run is free; an unknown cost cannot be budgeted.
    if limits.cost_per_run is None or limits.cost_per_run <= 0:
        return ["The real target needs a positive limits.cost_per_run estimate."]
    return []


def write_reports(folder: Path, summary: BenchmarkSummary) -> list[str]:
    write_atomic(folder, REPORT_FILE, summary_markdown(summary))
    return [REPORT_FILE]


def _say(line: str) -> None:
    print(line, flush=True)


def _report(summary: BenchmarkSummary, folder: Path) -> None:
    counts = summary.counts
    _say("")
    _say(f"Status: {summary.status} ({summary.profile} profile, {summary.scope} scope).")
    _say(
        f"Cells: {counts.passed_cells} passed, {counts.failed_cells} failed, "
        f"{counts.pending_cells} pending, {counts.error_cells} errors, of {counts.expected_cells}."
    )
    _say(f"Molds fired where expected: {detection(counts).text()}")
    _say(f"False alarms: {false_alarms(counts).text()}")
    _say(f"Controls detected: {controls(counts).text()}")
    for cell in summary.cells:
        if cell.outcome in ("failed", "error"):
            detail = ", ".join(cell.diagnostics)
            _say(f"  {cell.outcome}: {cell.case_id} {cell.language or ''} {detail}".rstrip())
    if summary.scope == "selection":
        _say("This is a selection: it does not prove the release or the full benchmark.")
    _say(f"Result: {folder / SUMMARY_FILE}")


def main(
    argv: Sequence[str] | None = None,
    *,
    root: Path | None = None,
    matrix_path: Path | None = None,
) -> int:
    try:
        arguments = parser().parse_args(argv)
    except SystemExit as stopped:
        return 0 if stopped.code == 0 else 2
    if arguments.profile == "real":
        problems = real_preflight(arguments, dict(os.environ))
        for problem in problems:
            print(problem, file=sys.stderr)
        if not problems:
            print(REAL_UNAVAILABLE, file=sys.stderr)
        return 2
    if arguments.max_cost is not None or arguments.real_config is not None:
        print("--max-cost and --real-config belong to the real profile.", file=sys.stderr)
        return 2
    try:
        options = BenchmarkOptions(
            profile=arguments.profile,
            release=arguments.release,
            frameworks=arguments.frameworks,
            molds=arguments.molds,
            output=None if arguments.output is None else str(arguments.output),
            max_runs=arguments.max_runs,
        )
    except ValueError:
        print("Invalid option; see --help.", file=sys.stderr)
        return 2
    cancel = threading.Event()
    previous = signal.getsignal(signal.SIGINT)

    def interrupt(number: int, frame: Any) -> None:
        cancel.set()
        _say("Interrupted: finishing the current run and saving a partial result.")

    signal.signal(signal.SIGINT, interrupt)
    try:
        outcome = run_benchmark(
            options,
            root=root or ROOT,
            say=_say,
            cancel=cancel,
            write_summary=write_reports,
            matrix_path=matrix_path,
        )
    except MatrixError as error:
        for problem in error.problems:
            print(f"Matrix: {problem}", file=sys.stderr)
        return 2
    except OptionsError as error:
        print(str(error), file=sys.stderr)
        return 2
    except StorageError as error:
        print(f"The result could not be saved ({error.code}).", file=sys.stderr)
        return 2
    finally:
        signal.signal(signal.SIGINT, previous)
    _report(outcome.summary, outcome.folder)
    return outcome.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
