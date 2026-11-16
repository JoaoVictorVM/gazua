"""Where issue exports live: ``.gazua/issues/<run-id>/``, one folder per run.

A folder is Gazua's only when its ``manifest.json`` names the owner ``gazua-issues``, the
folder's run id and exactly the files it holds, each named by a finding id. The manifest is
written with the files and marks a complete set. A set is published by staging the new folder,
moving the previous one to a backup and recording both in a journal, so an interruption is
rolled back by the next command. Several renames are never assumed to be one atomic commit.

Every path is derived from a validated run id or finding id and checked to stay inside the
managed root. Links, junctions and reparse points are refused and never followed, and nothing a
manifest says is ever used as a path to remove.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal, cast

from gazua.issues.models import (
    ISSUES_FOLDER,
    MANIFEST_OWNER,
    MANIFEST_VERSION,
    IssueExportError,
    IssueFile,
)
from gazua.reports.storage import GAZUA_FOLDER, MANIFEST, gazua_root, is_link
from gazua.runtime.evidence import EvidencePathError, safe_directory, write_atomic

RUN_ID: Final = re.compile(r"^GAZUA-run-[A-Za-z0-9-]+$")
ISSUE_FILE: Final = re.compile(r"^finding-[0-9a-f]{64}\.md$")
_JOURNAL: Final = re.compile(r"^\.journal-(GAZUA-run-[A-Za-z0-9-]+)\.json$")
_STAGING: Final = re.compile(r"^\.staging-(GAZUA-run-[A-Za-z0-9-]+)$")
_BACKUP: Final = re.compile(r"^\.backup-(GAZUA-run-[A-Za-z0-9-]+)$")
_TEMPORARY: Final = re.compile(r"^\.\.journal-GAZUA-run-[A-Za-z0-9-]+\.json-[^/\\]*\.tmp$")

Comparison = Literal["absent", "same", "managed", "unmanaged"]


@dataclass(frozen=True, slots=True)
class ExportManifest:
    run_id: str
    source_digest: str
    guide_revision: int
    template_version: int
    include_attack: bool
    files: tuple[tuple[str, str], ...]

    def data(self) -> dict[str, Any]:
        return {
            "owner": MANIFEST_OWNER,
            "version": MANIFEST_VERSION,
            "run_id": self.run_id,
            "source_digest": self.source_digest,
            "guide_revision": self.guide_revision,
            "template_version": self.template_version,
            "include_attack": self.include_attack,
            "files": [{"name": name, "sha256": digest} for name, digest in self.files],
        }

    def text(self) -> str:
        return json.dumps(self.data(), indent=2) + "\n"


def digest(content: str | bytes) -> str:
    data = content.encode("utf-8") if isinstance(content, str) else content
    return hashlib.sha256(data).hexdigest()


def build_manifest(
    run_id: str,
    source_digest: str,
    guide_revision: int,
    template_version: int,
    include_attack: bool,
    issues: Sequence[IssueFile],
) -> ExportManifest:
    return ExportManifest(
        run_id=run_id,
        source_digest=source_digest,
        guide_revision=guide_revision,
        template_version=template_version,
        include_attack=include_attack,
        files=tuple(sorted((item.name, digest(item.content)) for item in issues)),
    )


def issues_root(root: Path) -> Path:
    return gazua_root(root) / ISSUES_FOLDER


def relative_folder(run_id: str) -> str:
    return f"{GAZUA_FOLDER}/{ISSUES_FOLDER}/{run_id}"


def _checked_run_id(run_id: str) -> str:
    if not RUN_ID.fullmatch(run_id):
        raise IssueExportError("issues_path_refused")
    return run_id


def _managed_root(root: Path, *, create: bool) -> Path | None:
    """``.gazua/issues`` as a plain directory inside the project, or None when absent."""
    folder = gazua_root(root)
    issues = folder / ISSUES_FOLDER
    for path in (folder, issues):
        if is_link(path) or (path.exists() and not path.is_dir()):
            raise IssueExportError("issues_path_refused")
    if not create:
        return issues if issues.is_dir() else None
    try:
        return safe_directory(root, GAZUA_FOLDER, ISSUES_FOLDER)
    except EvidencePathError:
        raise IssueExportError("issues_path_refused") from None


def _inside(managed: Path, path: Path) -> bool:
    return path.parent == managed and path.resolve().parent == managed.resolve()


def read_manifest(folder: Path) -> dict[str, Any] | None:
    """The folder's manifest when it proves the folder is a complete managed export."""
    path = folder / MANIFEST
    if is_link(folder) or not folder.is_dir() or is_link(path) or not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    found = cast("dict[str, Any]", data)
    listed: object = found.get("files")
    if (
        found.get("owner") != MANIFEST_OWNER
        or found.get("version") != MANIFEST_VERSION
        or found.get("run_id") != folder.name
        or not isinstance(listed, list)
    ):
        return None
    names: list[str] = []
    for item in cast("list[object]", listed):
        if not isinstance(item, dict):
            return None
        name: object = cast("dict[str, object]", item).get("name")
        sha: object = cast("dict[str, object]", item).get("sha256")
        if not isinstance(name, str) or not ISSUE_FILE.fullmatch(name):
            return None
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
            return None
        names.append(name)
    if len(set(names)) != len(names):
        return None
    try:
        present = {child.name for child in folder.iterdir()}
    except OSError:
        return None
    if present != {MANIFEST, *names}:
        return None
    if any(is_link(folder / name) or not (folder / name).is_file() for name in names):
        return None
    return found


def _same(folder: Path, manifest: ExportManifest, issues: Sequence[IssueFile]) -> bool:
    try:
        if (folder / MANIFEST).read_bytes() != manifest.text().encode("utf-8"):
            return False
        return all(
            (folder / item.name).read_bytes() == item.content.encode("utf-8") for item in issues
        )
    except OSError:
        return False


def compare(root: Path, manifest: ExportManifest, issues: Sequence[IssueFile]) -> Comparison:
    """How the current folder of this run stands against the export about to be written."""
    managed = _managed_root(root, create=False)
    if managed is None:
        return "absent"
    target = managed / _checked_run_id(manifest.run_id)
    if is_link(target):
        raise IssueExportError("issues_path_refused")
    if not target.exists():
        return "absent"
    if not target.is_dir():
        raise IssueExportError("issues_path_refused")
    if read_manifest(target) is None:
        return "unmanaged"
    return "same" if _same(target, manifest, issues) else "managed"


def _remove_managed(managed: Path, folder: Path) -> None:
    """Removes a folder of the managed root only after proving it holds no link."""
    if not _inside(managed, folder) or is_link(folder):
        raise IssueExportError("issues_path_refused")
    for current, directories, files in os.walk(folder, followlinks=False):
        base = Path(current)
        if any(is_link(base / name) for name in (*directories, *files)):
            raise IssueExportError("issues_path_refused")
    shutil.rmtree(folder)


def recover_exports(root: Path) -> int:
    """Rolls back every publication an interruption left half done. Returns how many."""
    managed = _managed_root(root, create=False)
    if managed is None:
        return 0
    recovered = 0
    for child in sorted(managed.iterdir()):
        match = _JOURNAL.fullmatch(child.name)
        if match is None or is_link(child) or not child.is_file():
            continue
        run_id = match.group(1)
        target = managed / run_id
        backup = managed / f".backup-{run_id}"
        staging = managed / f".staging-{run_id}"
        try:
            if backup.is_dir() and not is_link(backup):
                if target.exists() or is_link(target):
                    _remove_managed(managed, target)
                os.replace(backup, target)
            elif target.exists() and read_manifest(target) is not None:
                previous = json.loads(child.read_text(encoding="utf-8")).get("previous")
                if previous is False:
                    _remove_managed(managed, target)
            if staging.exists():
                _remove_managed(managed, staging)
            child.unlink()
        except (OSError, ValueError, AttributeError):
            raise IssueExportError("issues_recovery_failed") from None
        recovered += 1
    return recovered


def publish(
    root: Path,
    manifest: ExportManifest,
    issues: Sequence[IssueFile],
    *,
    before_swap: Callable[[], None] | None = None,
) -> None:
    """Replaces the run's export folder as a recoverable transaction.

    The caller already compared the folder and decided it may be replaced. A failure restores
    the previous set; ``issues_recovery_failed`` means even that failed and the journal stays.
    """
    managed = _managed_root(root, create=True)
    if managed is None:  # pragma: no cover - created above
        raise IssueExportError("issues_path_refused")
    recover_exports(root)
    run_id = _checked_run_id(manifest.run_id)
    target = managed / run_id
    staging = managed / f".staging-{run_id}"
    backup = managed / f".backup-{run_id}"
    journal = managed / f".journal-{run_id}.json"
    previous = target.exists()
    try:
        for leftover in (staging, backup):
            if leftover.exists() or is_link(leftover):
                _remove_managed(managed, leftover)
        safe_directory(managed, staging.name)
        for item in issues:
            if not ISSUE_FILE.fullmatch(item.name):
                raise IssueExportError("issues_path_refused")
            write_atomic(staging / item.name, item.content)
        write_atomic(staging / MANIFEST, manifest.text())
        write_atomic(journal, json.dumps({"version": 1, "previous": previous}) + "\n")
        if previous:
            if read_manifest(target) is None:
                raise IssueExportError("issues_unmanaged_destination")
            os.replace(target, backup)
        if before_swap is not None:
            before_swap()
        os.replace(staging, target)
    except (OSError, EvidencePathError, IssueExportError, KeyboardInterrupt) as error:
        try:
            recover_exports(root)
            if staging.exists():
                _remove_managed(managed, staging)
        except (OSError, IssueExportError):
            raise IssueExportError("issues_recovery_failed") from None
        if isinstance(error, KeyboardInterrupt):
            raise
        if isinstance(error, IssueExportError):
            raise
        raise IssueExportError("issues_write_failed") from None
    journal.unlink()
    if backup.exists():
        with contextlib.suppress(OSError, IssueExportError):
            _remove_managed(managed, backup)


@dataclass(slots=True)
class CleanedExports:
    removed: int = 0
    pending: list[str] | None = None


def clean_exports(root: Path) -> CleanedExports:
    """Removes every managed export folder and leftover; unknown entries stay. Caller locks."""
    result = CleanedExports(pending=[])
    try:
        managed = _managed_root(root, create=False)
    except IssueExportError:
        return result
    if managed is None:
        return result
    with contextlib.suppress(IssueExportError):
        recover_exports(root)
    for child in sorted(managed.iterdir()):
        name = child.name
        if is_link(child):
            continue
        try:
            if RUN_ID.fullmatch(name) and read_manifest(child) is not None:
                _remove_managed(managed, child)
                result.removed += 1
            elif (_STAGING.fullmatch(name) or _BACKUP.fullmatch(name)) and child.is_dir():
                _remove_managed(managed, child)
            elif (_JOURNAL.fullmatch(name) or _TEMPORARY.fullmatch(name)) and child.is_file():
                child.unlink()
        except (OSError, IssueExportError):
            cast("list[str]", result.pending).append(f"{relative_folder(name)}")
    with contextlib.suppress(OSError):
        if not any(managed.iterdir()):
            managed.rmdir()
    return result
