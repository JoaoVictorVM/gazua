"""Where a benchmark run writes: a new folder per run, atomic files and confined references.

A run never reuses or deletes an earlier folder. Every path it stores is relative to its own
folder and is checked against links and reparse points before it is written or read back.
"""

from __future__ import annotations

import contextlib
import os
import secrets
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Final

from .models import relative_problem

DEFAULT_PARENT: Final = Path(".gazua") / "benchmarks"


class StorageError(Exception):
    """The benchmark folder cannot be used; ``code`` is a closed, safe identifier."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _is_link(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    reparse = getattr(info, "st_reparse_tag", 0)
    return path.is_symlink() or bool(reparse)


def new_run_id() -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{secrets.token_hex(4)}"


def create_output(requested: Path | None, root: Path) -> Path:
    """Creates the run's new folder; an existing path or a link on the way is refused."""
    target = requested if requested is not None else root / DEFAULT_PARENT / new_run_id()
    target = target if target.is_absolute() else root / target
    if target.exists() or _is_link(target):
        raise StorageError("output_exists")
    # Folders above the project are the user's business; below it, a link could redirect writes.
    for parent in target.parents:
        if parent == root or root not in parent.parents:
            break
        if _is_link(parent):
            raise StorageError("output_link")
    try:
        target.mkdir(parents=True)
    except OSError:
        raise StorageError("output_unwritable") from None
    return target


def contained(folder: Path, relative: str) -> Path:
    """The file a stored reference names, refused when it leaves the folder or is a link."""
    try:
        relative_problem(relative)
    except ValueError:
        raise StorageError("reference_outside") from None
    path = folder.joinpath(*PurePosixPath(relative).parts)
    current = folder
    for part in PurePosixPath(relative).parts:
        current = current / part
        if _is_link(current):
            raise StorageError("reference_link")
    return path


def reference(folder: Path, path: Path) -> str:
    """``path`` as a POSIX reference relative to ``folder``."""
    try:
        relative = path.resolve().relative_to(folder.resolve())
    except ValueError:
        raise StorageError("reference_outside") from None
    text = relative.as_posix()
    contained(folder, text)
    return text


def write_atomic(folder: Path, name: str, text: str) -> Path:
    """Writes through a temporary file in the same folder, then replaces the target."""
    target = contained(folder, name)
    temporary = target.with_name(f".{target.name}.{secrets.token_hex(4)}.tmp")
    try:
        temporary.write_text(text, encoding="utf-8", newline="\n")
        os.replace(temporary, target)
    except OSError:
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise StorageError("write_failed") from None
    return target


__all__ = [
    "DEFAULT_PARENT",
    "StorageError",
    "contained",
    "create_output",
    "new_run_id",
    "reference",
    "write_atomic",
]
