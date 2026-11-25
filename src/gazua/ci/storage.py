"""The managed ``.gazua/ci/`` folder: projections written atomically, removed only when owned.

A marker file identifies the folder as Gazua's. Each file is written to an exclusive temporary
name, checked and then moved into place, so a reader never sees half a projection. Cleaning
refuses links and unknown files and never counts the folder as a run.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from gazua.ci.models import CI_FOLDER
from gazua.reports.storage import GAZUA_FOLDER, is_link
from gazua.runtime.evidence import EvidencePathError, safe_directory

MARKER: Final = ".gazua-ci.json"
EVIDENCE_FOLDER: Final = "evidence"
SUMMARY_FILE: Final = "summary.json"
COMMENT_FILE: Final = "comment.md"
COMMENT_DATA_FILE: Final = "comment.json"
SARIF_FILE: Final = "gazua.sarif"
MANAGED_FILES: Final = (MARKER, SUMMARY_FILE, COMMENT_FILE, COMMENT_DATA_FILE, SARIF_FILE)
_MARKER_CONTENT: Final = json.dumps({"owner": "gazua", "version": 1}) + "\n"


class CiStorageError(Exception):
    """A projection could not be published. ``code`` is safe to print."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def relative(name: str) -> str:
    return f"{GAZUA_FOLDER}/{CI_FOLDER}/{name}"


def ci_folder(root: Path) -> Path:
    """``.gazua/ci`` with its marker, created one level at a time without following links."""
    try:
        folder = safe_directory(root, GAZUA_FOLDER, CI_FOLDER)
    except (EvidencePathError, OSError):
        raise CiStorageError("ci_path_refused") from None
    marker = folder / MARKER
    if is_link(marker) or (marker.exists() and not marker.is_file()):
        raise CiStorageError("ci_path_refused")
    if not marker.is_file():
        write_checked(marker, _MARKER_CONTENT)
    return folder


def write_checked(path: Path, content: str, check: Callable[[str], object] | None = None) -> None:
    """Writes ``content`` through an exclusive temporary file, reads it back, then replaces."""
    if is_link(path) or (path.exists() and not path.is_file()):
        raise CiStorageError("ci_path_refused")
    try:
        handle, temporary = tempfile.mkstemp(
            dir=path.parent, prefix=f".{path.name}-", suffix=".tmp"
        )
    except OSError:
        raise CiStorageError("ci_write_failed") from None
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        written = Path(temporary).read_text(encoding="utf-8")
        if written != content:
            raise CiStorageError("ci_write_failed")
        if check is not None:
            check(written)
        os.replace(temporary, path)
    except OSError:
        Path(temporary).unlink(missing_ok=True)
        raise CiStorageError("ci_write_failed") from None
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def publish(
    root: Path, name: str, content: str, check: Callable[[str], object] | None = None
) -> str:
    """One projection under ``.gazua/ci``; returns its path relative to the project root."""
    if name not in MANAGED_FILES or name == MARKER:
        raise CiStorageError("ci_path_refused")
    write_checked(ci_folder(root) / name, content, check)
    return relative(name)


def _has_link(folder: Path) -> bool:
    for current, directories, files in os.walk(folder, followlinks=False):
        base = Path(current)
        if any(is_link(base / item) for item in (*directories, *files)):
            return True
    return False


def managed(root: Path) -> Path | None:
    """The CI folder when its marker is valid and it holds only Gazua's files."""
    folder = root / GAZUA_FOLDER / CI_FOLDER
    marker = folder / MARKER
    if is_link(root / GAZUA_FOLDER) or is_link(folder) or not folder.is_dir():
        return None
    if is_link(marker) or not marker.is_file():
        return None
    try:
        content = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if content != {"owner": "gazua", "version": 1}:
        return None
    for child in folder.iterdir():
        name = child.name
        if is_link(child):
            return None
        if name == EVIDENCE_FOLDER and child.is_dir():
            if _has_link(child):
                return None
            continue
        if name in MANAGED_FILES and child.is_file():
            continue
        if name.startswith(".") and name.endswith(".tmp") and child.is_file():
            continue
        return None
    return folder


@dataclass(slots=True)
class CiCleanResult:
    removed: bool = False
    pending: list[str] = field(default_factory=list[str])


def clean_ci(root: Path) -> CiCleanResult:
    """Removes ``.gazua/ci`` when managed; anything unexpected keeps it, as unknown files stay."""
    result = CiCleanResult()
    owned = managed(root)
    if owned is None:
        return result
    try:
        shutil.rmtree(owned)
        result.removed = True
    except OSError:
        result.pending.append(f"{GAZUA_FOLDER}/{CI_FOLDER}")
    return result


def reset_evidence(root: Path) -> Path:
    """An empty ``.gazua/ci/evidence`` for the staging of one run's artifact."""
    folder = ci_folder(root)
    target = folder / EVIDENCE_FOLDER
    if is_link(target):
        raise CiStorageError("ci_path_refused")
    if target.exists():
        if not target.is_dir() or _has_link(target):
            raise CiStorageError("ci_path_refused")
        with contextlib.suppress(FileNotFoundError):
            shutil.rmtree(target)
    try:
        return safe_directory(folder, EVIDENCE_FOLDER)
    except (EvidencePathError, OSError):
        raise CiStorageError("ci_path_refused") from None
