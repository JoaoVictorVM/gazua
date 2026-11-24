"""Checks on a TypeScript target before any Node process starts.

The module is a relative path inside the project, a regular ``.js`` or ``.mjs`` file reached
without links, URLs, package specifiers or traversal. Node is the ``node`` the system resolves;
no configuration, mold, response or variable chooses another command.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Final

from gazua.diagnostics import ConfigError, Diagnostic
from gazua.typescript.models import MINIMUM_NODE_MAJOR

EXTENSIONS: Final = (".js", ".mjs")
NODE_VERSION_TIMEOUT: Final = 10.0
_FORBIDDEN: Final = ("\\", ":", "?", "#", "\x00")


def _failure(code: str, message: str, field: str = "typescript.module") -> ConfigError:
    return ConfigError([Diagnostic(code=code, field=field, message=message)])


def module_path_problem(module: str) -> str | None:
    """Why ``module`` cannot name a compiled module of the project, or None when it can."""
    if not module or any(character in module for character in _FORBIDDEN):
        return "Expected a relative path with forward slashes, without URL or drive."
    path = PurePosixPath(module)
    if path.is_absolute() or ".." in path.parts or "" in module.split("/"):
        return "The module must stay inside the project, without .. or an absolute path."
    if not module.endswith(EXTENSIONS):
        return "Expected compiled JavaScript ESM (.js or .mjs); Gazua does not run .ts files."
    return None


def check_module(root: Path, module: str) -> Path:
    """The module's path inside ``root``, a regular file reached without symbolic links."""
    problem = module_path_problem(module)
    if problem is not None:
        raise _failure("typescript_module_invalid", problem)
    base = root.resolve()
    current = base
    for part in PurePosixPath(module).parts:
        if part == ".":
            continue
        current = current / part
        try:
            status = current.lstat()
        except OSError:
            raise _failure(
                "typescript_module_missing",
                "The compiled module does not exist; build the project before running Gazua.",
            ) from None
        if stat.S_ISLNK(status.st_mode) or _is_junction(current):
            raise _failure("typescript_module_invalid", "The module path cannot go through a link.")
    if not current.is_file():
        raise _failure("typescript_module_invalid", "The module must be a regular file.")
    try:
        current.resolve().relative_to(base)
    except ValueError:
        raise _failure(
            "typescript_module_invalid", "The module must stay inside the project."
        ) from None
    return current


def _is_junction(path: Path) -> bool:
    is_junction = getattr(os.path, "isjunction", None)
    return bool(is_junction(path)) if callable(is_junction) else False


def module_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def node_executable() -> str:
    """The ``node`` the system resolves, or a configuration error with install guidance."""
    found = shutil.which("node")
    if found is None:
        raise _failure(
            "typescript_node_missing",
            f"Node.js {MINIMUM_NODE_MAJOR} or newer is required for a TypeScript target; "
            "install it and make node available on PATH.",
            "typescript",
        )
    return found


def node_version(executable: str) -> str:
    """The version ``node --version`` prints, checked against the supported minimum."""
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    try:
        completed = subprocess.run(  # noqa: S603
            [executable, "--version"],
            capture_output=True,
            timeout=NODE_VERSION_TIMEOUT,
            check=False,
            shell=False,
            creationflags=flags,
        )
    except (OSError, subprocess.SubprocessError):
        raise _failure(
            "typescript_node_missing", "node --version could not run.", "typescript"
        ) from None
    text = completed.stdout.decode("ascii", "replace").strip().removeprefix("v")
    major = text.split(".", 1)[0]
    if completed.returncode != 0 or not major.isdigit():
        raise _failure("typescript_node_missing", "node --version gave no version.", "typescript")
    if int(major) < MINIMUM_NODE_MAJOR:
        raise _failure(
            "typescript_node_unsupported",
            f"Node.js {MINIMUM_NODE_MAJOR} or newer is required; found {major}.",
            "typescript",
        )
    return text


__all__ = [
    "check_module",
    "module_path_problem",
    "module_sha256",
    "node_executable",
    "node_version",
]
