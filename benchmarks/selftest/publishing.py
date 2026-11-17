"""Readable artifacts of a result: ``summary.md`` and the README table, both derived from it.

Nothing here adds a number that the result's cells do not hold. Payloads, conversations,
canary values, finding ids and proof references stay out: the table keeps only rates with
their denominators, provenance and the gaps. ``--check`` compares the README with a fresh
result, so a hand edit or stale numbers fail instead of drifting.

    python -m benchmarks.selftest.publishing --from .gazua/benchmarks/<id>/benchmark.json
    python -m benchmarks.selftest.publishing --from <benchmark.json> --check
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from .metrics import Rate, controls, detection, false_alarms, rows
from .models import BenchmarkSummary, CellResult

README: Final = Path(__file__).resolve().parents[2] / "README.md"
START: Final = "<!-- benchmark:start -->"
END: Final = "<!-- benchmark:end -->"
SIMULATED_NOTE: Final = (
    "Simulated runs measure Gazua's own chain against synthetic targets with a scripted model. "
    "They are not a resistance rate of any commercial model."
)


def _short(commit: str | None) -> str:
    return commit[:12] if commit else "unknown"


def table_lines(summary: BenchmarkSummary) -> list[str]:
    lines = [
        "| Implementation | Mode | Language | Detection | False alarms | Unexpected findings "
        "| Coverage | Pending | Errors |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for row in rows(summary.cells):
        lines.append(
            f"| {row.framework} | {row.mode} | {row.language} | {row.detection.text()} "
            f"| {row.false_alarms.text()} | {row.unexpected_findings} | {row.coverage.text()} "
            f"| {row.pending} | {row.errors} |"
        )
    return lines


def _totals(summary: BenchmarkSummary) -> list[str]:
    counts = summary.counts
    checks = [cell for cell in summary.cells if cell.kind == "check"]
    passed_checks = sum(1 for cell in checks if cell.outcome == "passed")
    return [
        f"- Molds fired where expected: {detection(counts).text()}",
        f"- False alarms on targets that must stay quiet: {false_alarms(counts).text()}",
        f"- Controls detected by one-at-a-time mutation: {controls(counts).text()}",
        f"- Auxiliary checks passed: {Rate(passed_checks, len(checks)).text()}",
    ]


def readme_block(summary: BenchmarkSummary) -> str:
    """The README section for a release or full result. A selection is never published."""
    if summary.scope == "selection":
        raise ValueError("a selection result is not published")
    provenance = summary.provenance
    lines = [
        START,
        f"Profile `{summary.profile}`, catalog `{summary.catalog_release}`, "
        f"status `{summary.status}`, commit `{_short(provenance.commit)}`"
        f"{' (uncommitted changes)' if provenance.dirty else ''}, "
        f"matrix revision `{provenance.matrix_revision}`.",
        "",
        *_totals(summary),
        "",
        *table_lines(summary),
        "",
        SIMULATED_NOTE,
        END,
    ]
    return "\n".join(lines)


def _numbers(block: str) -> list[str]:
    """The lines a fresh run must reproduce exactly: totals and table, not provenance."""
    return [line for line in block.splitlines() if line.startswith(("- ", "|"))]


def current_block(readme: str) -> str | None:
    match = re.search(rf"{re.escape(START)}.*?{re.escape(END)}", readme, flags=re.DOTALL)
    return None if match is None else match.group(0)


def publish(readme: str, summary: BenchmarkSummary) -> str:
    block = readme_block(summary)
    current = current_block(readme)
    if current is None:
        raise ValueError("the README has no benchmark section markers")
    return readme.replace(current, block)


def check(readme: str, summary: BenchmarkSummary) -> list[str]:
    current = current_block(readme)
    if current is None:
        return ["the README has no benchmark section"]
    problems: list[str] = []
    if _numbers(current) != _numbers(readme_block(summary)):
        problems.append("the README numbers differ from this result; publish it again")
    if summary.status != "passed" and summary.scope == "release":
        problems.append("this release result did not pass")
    return problems


def _failing(cells: Sequence[CellResult]) -> list[str]:
    return [
        f"- `{cell.case_id}` ({cell.language or '-'}, {cell.variant or '-'}): {cell.outcome}, "
        f"{', '.join(cell.diagnostics) or cell.dependency or 'no detail'}"
        for cell in cells
        if cell.outcome in ("failed", "error")
    ]


def summary_markdown(summary: BenchmarkSummary) -> str:
    provenance = summary.provenance
    failing = _failing(summary.cells)
    pending = sorted({cell.dependency for cell in summary.cells if cell.dependency})
    lines = [
        "# Gazua self-test benchmark",
        "",
        f"Status: **{summary.status}**. Profile `{summary.profile}`, scope `{summary.scope}`, "
        f"catalog `{summary.catalog_release}`, simulated: {'yes' if summary.simulated else 'no'}.",
        "",
        f"Commit `{_short(provenance.commit)}`"
        f"{' with uncommitted changes' if provenance.dirty else ''}, Gazua "
        f"`{provenance.gazua_version or 'unknown'}`, {provenance.runtime}, matrix revision "
        f"`{provenance.matrix_revision}`.",
        "",
        "## Totals",
        "",
        *_totals(summary),
        "",
        "## By implementation, mode and language",
        "",
        *table_lines(summary),
        "",
        "## Cells that failed or could not run",
        "",
        *(failing or ["None."]),
        "",
        "## Pending dependencies",
        "",
        *([f"- {item}" for item in pending] or ["None."]),
        "",
        "## Known gaps outside this scope",
        "",
        *([f"- {item}" for item in summary.gaps] or ["None."]),
        "",
        SIMULATED_NOTE,
        "",
    ]
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m benchmarks.selftest.publishing")
    parser.add_argument("--from", dest="source", required=True, type=Path)
    parser.add_argument("--readme", type=Path, default=README)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        summary = BenchmarkSummary.model_validate_json(arguments.source.read_bytes())
        readme = arguments.readme.read_text(encoding="utf-8")
    except (OSError, ValueError) as error:
        print(f"Cannot read the result or the README: {type(error).__name__}.", file=sys.stderr)
        return 2
    if arguments.check:
        problems = check(readme, summary)
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1 if problems else 0
    try:
        updated = publish(readme, summary)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    arguments.readme.write_text(updated, encoding="utf-8", newline="\n")
    print(f"Published the {summary.scope} result into {arguments.readme.name}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["check", "main", "publish", "readme_block", "summary_markdown", "table_lines"]
