"""The demo's own folder: materialized once, recognized by its manifest, never overwritten.

A new or empty folder receives the packaged configuration, a ``.gitignore`` that covers
``.gazua/`` and the manifest, each created exclusively. An existing folder is accepted only when
its manifest is valid, its profile version is this package's and its configuration hash matches
the packaged one. Anything else is a conflict, before any target is imported, and unknown files
stay untouched. Links and junctions are refused, never followed.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Final

from pydantic import ValidationError

from gazua.demo import PROFILE, PROFILE_VERSION
from gazua.demo.models import DemoManifest

CONFIG_NAME: Final = "gazua.yaml"
GITIGNORE_NAME: Final = ".gitignore"
MANIFEST_NAME: Final = ".gazua-demo.json"
INDEX_NAME: Final = "index.html"
GITIGNORE_TEXT: Final = ".gazua/\n"
MANAGED: Final = (CONFIG_NAME, GITIGNORE_NAME, MANIFEST_NAME, INDEX_NAME, ".gazua")

CONFLICT: Final = "demo_workspace_conflict"
UNSAFE: Final = "demo_unsafe_path"
RESOURCE: Final = "demo_resource_invalid"

MESSAGES: Final = {
    CONFLICT: (
        "{path} is not a Gazua demo folder of this version, or its gazua.yaml was changed. "
        "Nothing was overwritten; choose another folder with --output."
    ),
    UNSAFE: "{path} is or contains a link or junction; the demo does not follow links.",
    RESOURCE: "The demo files installed with Gazua are invalid; reinstall Gazua.",
}


class DemoError(Exception):
    """A demo problem with its code; the message names the folder, never file contents."""

    def __init__(self, code: str, path: Path | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.path = path

    @property
    def message(self) -> str:
        return MESSAGES[self.code].format(path=self.path if self.path is not None else "")


@dataclass(frozen=True, slots=True)
class Workspace:
    root: Path
    config_path: Path
    created: bool

    @property
    def index_path(self) -> Path:
        return self.root / INDEX_NAME


def packaged_config() -> bytes:
    try:
        return files("gazua.demo").joinpath("resources", CONFIG_NAME).read_bytes()
    except OSError:
        raise DemoError(RESOURCE) from None


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def is_link(path: Path) -> bool:
    """A symlink, junction or other reparse point; never followed."""
    try:
        status = path.lstat()
    except FileNotFoundError:
        return False
    if path.is_symlink():
        return True
    return bool(getattr(status, "st_file_attributes", 0) & 0x400)


def _check_links(root: Path) -> None:
    if is_link(root):
        raise DemoError(UNSAFE, root)
    for name in MANAGED:
        if is_link(root / name):
            raise DemoError(UNSAFE, root)


def _create(path: Path, content: bytes) -> None:
    """Writes a new file atomically and exclusively: an existing one makes it a conflict."""
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=".gazua-demo-", suffix=".tmp")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(content)
        try:
            os.link(temporary, path)
        except FileExistsError:
            raise DemoError(CONFLICT, path.parent) from None
        except OSError:
            # Some file systems have no hard links; exclusive creation still never overwrites.
            try:
                with path.open("xb") as stream:
                    stream.write(content)
            except FileExistsError:
                raise DemoError(CONFLICT, path.parent) from None
    finally:
        with contextlib.suppress(OSError):
            Path(temporary).unlink()


def _manifest(config: bytes) -> bytes:
    document = DemoManifest(
        schema_version=1,
        profile=PROFILE,
        profile_version=PROFILE_VERSION,
        config_sha256=sha256(config),
    )
    return (json.dumps(document.model_dump(), indent=2) + "\n").encode("utf-8")


def _read_manifest(path: Path) -> DemoManifest:
    try:
        return DemoManifest.model_validate_json(path.read_bytes())
    except (OSError, ValidationError, ValueError):
        raise DemoError(CONFLICT, path.parent) from None


def _accept_existing(root: Path, config: bytes) -> bool:
    """True when the folder must be filled, False when it is already a valid workspace."""
    manifest_path = root / MANIFEST_NAME
    if not manifest_path.exists():
        if any(root.iterdir()):
            raise DemoError(CONFLICT, root)
        return True
    manifest = _read_manifest(manifest_path)
    expected = sha256(config)
    if manifest.profile_version != PROFILE_VERSION or manifest.config_sha256 != expected:
        raise DemoError(CONFLICT, root)
    config_path = root / CONFIG_NAME
    if not config_path.is_file():
        raise DemoError(CONFLICT, root)
    try:
        current = config_path.read_bytes()
    except OSError:
        raise DemoError(CONFLICT, root) from None
    if sha256(current) != expected:
        raise DemoError(CONFLICT, root)
    if not (root / GITIGNORE_NAME).exists():
        _create(root / GITIGNORE_NAME, GITIGNORE_TEXT.encode("utf-8"))
    return False


def prepare_workspace(output: Path) -> Workspace:
    """The demo folder at ``output``, created or recognized. Raises ``DemoError``."""
    root = Path(os.path.abspath(output))
    config = packaged_config()
    _check_links(root)
    if root.exists() and not root.is_dir():
        raise DemoError(CONFLICT, root)
    fill = True
    if root.is_dir():
        fill = _accept_existing(root, config)
    else:
        try:
            root.mkdir(parents=True)
        except FileExistsError:
            raise DemoError(CONFLICT, root) from None
        except OSError:
            raise DemoError(CONFLICT, root) from None
    if fill:
        # The manifest goes last: a folder without it was never a complete workspace.
        _create(root / CONFIG_NAME, config)
        _create(root / GITIGNORE_NAME, GITIGNORE_TEXT.encode("utf-8"))
        _create(root / MANIFEST_NAME, _manifest(config))
    _check_links(root)
    return Workspace(root=root, config_path=root / CONFIG_NAME, created=fill)


__all__ = [
    "CONFIG_NAME",
    "CONFLICT",
    "INDEX_NAME",
    "MANIFEST_NAME",
    "RESOURCE",
    "UNSAFE",
    "DemoError",
    "Workspace",
    "packaged_config",
    "prepare_workspace",
    "sha256",
]
