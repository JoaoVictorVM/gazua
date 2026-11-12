"""Mutual exclusion, retention of the last runs and ``gazua clean``.

A command that creates or changes ``.gazua/`` holds an operating system lock on
``.gazua/.lifecycle.lock`` for its whole cycle, taken before the target is imported, so clean
and retention never run beside an active run. The lock file may stay after a crash; only the
lock itself means activity. Removal never follows links and only touches folders that Gazua's
manifest or private marker identifies as its own.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import IO, Final

from gazua.reports.models import ReportDiagnostic
from gazua.reports.storage import (
    BACKUP,
    GAZUA_FOLDER,
    JOURNAL,
    LATEST_FILES,
    MANIFEST,
    RUNS_FOLDER,
    STAGING,
    gazua_root,
    is_link,
    recover_latest,
)
from gazua.runtime.evidence import (
    PRIVATE_FOLDER,
    PRIVATE_MARKER,
    EvidencePathError,
    safe_directory,
)

RETAINED_RUNS: Final = 20
LOCK_FILE: Final = ".lifecycle.lock"
_RUN_ID: Final = re.compile(r"^GAZUA-run-[A-Za-z0-9-]+$")
_UTC: Final = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$")


class LockBusy(Exception):
    """Another Gazua command holds the lock of this project."""


class LifecycleLock:
    """A non-blocking exclusive lock, released when the command or its process ends."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._handle: IO[bytes] | None = None

    def __enter__(self) -> LifecycleLock:
        try:
            folder = safe_directory(self.root, GAZUA_FOLDER)
        except EvidencePathError:
            raise OSError("the .gazua folder is not a plain directory") from None
        path = folder / LOCK_FILE
        if is_link(path):
            raise LockBusy
        handle = path.open("a+b")
        try:
            _lock(handle)
        except OSError:
            handle.close()
            raise LockBusy from None
        self._handle = handle
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        trace: TracebackType | None,
    ) -> None:
        if self._handle is not None:
            with contextlib.suppress(OSError):
                _unlock(self._handle)
            self._handle.close()
            self._handle = None


if os.name == "nt":
    import msvcrt

    def _lock(handle: IO[bytes]) -> None:
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)

    def _unlock(handle: IO[bytes]) -> None:
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _lock(handle: IO[bytes]) -> None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(handle: IO[bytes]) -> None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@dataclass(frozen=True, slots=True)
class ManagedRun:
    run_id: str
    created_at: str
    path: Path


def _manifest(folder: Path) -> ManagedRun | None:
    path = folder / MANIFEST
    if is_link(folder) or is_link(path) or not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    run_id, created = data.get("run_id"), data.get("created_at")  # type: ignore[union-attr]
    if (
        data.get("owner") != "gazua"  # type: ignore[union-attr]
        or data.get("version") != 1  # type: ignore[union-attr]
        or data.get("complete") is not True  # type: ignore[union-attr]
        or not isinstance(run_id, str)
        or run_id != folder.name
        or not _RUN_ID.fullmatch(run_id)
        or not isinstance(created, str)
        or not _UTC.fullmatch(created)
    ):
        return None
    return ManagedRun(run_id, created, folder)


def _runs_root(root: Path) -> Path | None:
    folder = gazua_root(root)
    runs = folder / RUNS_FOLDER
    if is_link(folder) or is_link(runs) or not runs.is_dir():
        return None
    return runs


def managed_runs(root: Path) -> list[ManagedRun]:
    """Finished runs recognized by a valid manifest, oldest first."""
    runs = _runs_root(root)
    if runs is None:
        return []
    found = [item for item in (_manifest(child) for child in runs.iterdir()) if item is not None]
    return sorted(found, key=lambda item: (item.created_at, item.run_id))


def _residue(folder: Path) -> bool:
    """A run folder without manifest that only holds an engine left by an abrupt stop."""
    if is_link(folder) or not _RUN_ID.fullmatch(folder.name) or (folder / MANIFEST).exists():
        return False
    engine = folder / "engine"
    marker = engine / PRIVATE_FOLDER / PRIVATE_MARKER
    return not is_link(engine) and marker.is_file() and not is_link(marker)


def _has_link(folder: Path) -> bool:
    for current, directories, files in os.walk(folder, followlinks=False):
        base = Path(current)
        if any(is_link(base / name) for name in (*directories, *files)):
            return True
    return False


def remove_run(root: Path, folder: Path) -> bool:
    """Removes one run folder inside ``.gazua/runs``; refuses links and anything outside."""
    runs = _runs_root(root)
    if runs is None or is_link(folder) or folder.parent != runs:
        return False
    resolved_runs = runs.resolve()
    resolved = folder.resolve()
    if resolved.parent != resolved_runs or resolved in (resolved_runs, root.resolve()):
        return False
    if _has_link(folder):
        return False
    shutil.rmtree(folder)
    return True


def apply_retention(root: Path, keep: int = RETAINED_RUNS) -> tuple[int, list[ReportDiagnostic]]:
    """Keeps the newest ``keep`` finished runs. Unknown folders are never counted or removed."""
    runs = managed_runs(root)
    diagnostics: list[ReportDiagnostic] = []
    excess = runs[: max(0, len(runs) - keep)]
    removed = 0
    for item in excess:
        try:
            if remove_run(root, item.path):
                removed += 1
            else:
                diagnostics.append(ReportDiagnostic(code="retention_refused", level="error"))
        except OSError:
            diagnostics.append(ReportDiagnostic(code="retention_failed", level="error"))
    return len(runs) - removed, diagnostics


@dataclass(slots=True)
class CleanResult:
    runs: int = 0
    files: int = 0
    pending: list[str] = field(default_factory=list[str])

    @property
    def removed(self) -> int:
        return self.runs + self.files


def clean_runs(root: Path) -> CleanResult:
    """Removes every Gazua-owned run, the latest set and managed temporary files.

    The caller holds the lock. ``.gazua`` itself, the lock file and unknown files stay.
    """
    result = CleanResult()
    folder = gazua_root(root)
    if is_link(folder) or not folder.is_dir():
        return result
    recover_latest(root)
    runs = _runs_root(root)
    if runs is not None:
        for child in sorted(runs.iterdir()):
            if _manifest(child) is None and not _residue(child):
                continue
            try:
                if remove_run(root, child):
                    result.runs += 1
                else:
                    result.pending.append(f"{GAZUA_FOLDER}/{RUNS_FOLDER}/{child.name}")
            except OSError:
                result.pending.append(f"{GAZUA_FOLDER}/{RUNS_FOLDER}/{child.name}")
    for name in LATEST_FILES:
        path = folder / name
        if is_link(path) or not path.is_file():
            continue
        try:
            path.unlink()
            result.files += 1
        except OSError:
            result.pending.append(f"{GAZUA_FOLDER}/{name}")
    for name in (STAGING, BACKUP):
        path = folder / name
        if path.is_dir() and not is_link(path):
            with contextlib.suppress(OSError):
                shutil.rmtree(path)
    journal = folder / JOURNAL
    if journal.is_file() and not is_link(journal):
        with contextlib.suppress(OSError):
            journal.unlink()
    return result


_GITIGNORE_RULES: Final = frozenset(
    {".gazua", ".gazua/", "/.gazua", "/.gazua/", ".gazua/*", "/.gazua/*"}
)


def _simple_rule(root: Path) -> bool:
    path = root / ".gitignore"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return False
    return any(line.strip() in _GITIGNORE_RULES for line in lines)


def gitignore_covers(root: Path) -> bool:
    """Whether a project ``.gitignore`` covers ``.gazua/``. Nothing is ever edited.

    Git's own matching decides when Git is available; a rule that only lives in
    ``.git/info/exclude`` or a global excludes file does not count. Without Git, only the
    simple ``.gazua/`` rule in the root ``.gitignore`` is recognized; in doubt, it warns.
    """
    import subprocess

    git = shutil.which("git")
    if git is not None:
        try:
            completed = subprocess.run(  # noqa: S603
                [git, "-C", str(root), "check-ignore", "--no-index", "-v", "--", ".gazua/"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            completed = None
        if completed is not None and completed.returncode in (0, 1):
            if completed.returncode == 1:
                return False
            source = completed.stdout.split("\t", 1)[0].rsplit(":", 2)[0]
            return Path(source).name == ".gitignore" and ".git/" not in source.replace("\\", "/")
    return _simple_rule(root)
