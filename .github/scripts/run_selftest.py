"""The CI gate of the self-test benchmark: the release profile, changed molds and the README.

1. The release profile of the packaged catalog must pass: every mold of the release fires on
   the vulnerable target and stays quiet on the hardened one, every control is detected.
2. With a reliable Git base, every changed or new mold, of any release, must have its executable
   target pair and pass it; a mold whose cells are pending blocks the change.
3. The README numbers must match this run.

Without a reliable base (a new branch or a tag), step 2 cannot know what changed and the release
gate of step 1 is the one that applies. Mold ids are read from file names in the catalog folder
and checked against the matrix; nothing from the diff is passed to a shell.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from benchmarks.selftest.coverage import (  # noqa: E402
    changed_molds_problems,
    load_matrix,
    load_packaged_catalog,
)

CATALOG = "src/gazua/catalog/builtin"
MOLD_FILE = re.compile(r"^src/gazua/catalog/builtin/([a-z0-9][a-z0-9-]*)\.yaml$")
Runner = Callable[[Sequence[str]], int]


def _git(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments], cwd=ROOT, capture_output=True, text=True, check=False
    )


def reliable_base(base: str | None) -> str | None:
    if not base or not re.fullmatch(r"[0-9a-f]{40}", base) or set(base) == {"0"}:
        return None
    return base if _git("cat-file", "-e", f"{base}^{{commit}}").returncode == 0 else None


def _manifest_ids(text: str) -> dict[str, str]:
    try:
        return {item["id"]: item["introduced_in"] for item in json.loads(text)["molds"]}
    except (ValueError, KeyError, TypeError):
        return {}


def changed_molds(base: str) -> list[str]:
    names = _git("diff", "--name-only", base, "HEAD", "--", CATALOG).stdout.splitlines()
    changed = {match.group(1) for name in names if (match := MOLD_FILE.match(name))}
    if f"{CATALOG}/manifest.json" in names:
        before = _manifest_ids(_git("show", f"{base}:{CATALOG}/manifest.json").stdout)
        now = _manifest_ids((ROOT / CATALOG / "manifest.json").read_text(encoding="utf-8"))
        changed |= {mold for mold, release in now.items() if before.get(mold) != release}
    current = {entry.id for entry in load_packaged_catalog().entries}
    return sorted(changed & current)


def run_benchmark(arguments: Sequence[str]) -> int:
    completed = subprocess.run(
        [sys.executable, "-m", "benchmarks.selftest", *arguments], cwd=ROOT, check=False
    )
    return completed.returncode


def check_readme(result: Path) -> int:
    completed = subprocess.run(
        [sys.executable, "-m", "benchmarks.selftest.publishing", "--from", str(result), "--check"],
        cwd=ROOT,
        check=False,
    )
    return completed.returncode


def gate(
    base: str | None,
    *,
    run: Runner = run_benchmark,
    changed: Callable[[str], list[str]] = changed_molds,
    readme: Callable[[Path], int] = check_readme,
    workdir: Path | None = None,
) -> int:
    folder = workdir or Path(tempfile.mkdtemp(prefix="gazua-selftest-"))
    release = folder / "release"
    code = run(["--profile", "release", "--output", str(release)])
    if code != 0:
        print("The release benchmark did not pass.", file=sys.stderr)
        return code
    if readme(release / "benchmark.json") != 0:
        return 1
    reference = reliable_base(base)
    if reference is None:
        print("No reliable Git base: the release benchmark above is the gate for this change.")
        return 0
    molds = changed(reference)
    if not molds:
        print("No mold changed.")
        return 0
    matrix, _ = load_matrix()
    problems = changed_molds_problems(matrix, molds)
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return 1
    catalog = load_packaged_catalog()
    in_release = {entry.id for entry in catalog.in_release(catalog.default_release)}
    later = [mold for mold in molds if mold not in in_release]
    if not later:
        return 0
    selection = [part for mold in later for part in ("--mold", mold)]
    return run(["--profile", "full", "--output", str(folder / "changed"), *selection])


if __name__ == "__main__":
    raise SystemExit(gate(os.environ.get("GAZUA_BENCHMARK_BASE")))
