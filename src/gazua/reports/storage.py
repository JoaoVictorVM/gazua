"""Where reports live: one history folder per run and a recoverable latest set.

Each run writes ``.gazua/runs/<run-id>/`` with ``run.json``, both reports and, only after
those are complete, a ``manifest.json`` that marks the folder as a finished Gazua run. The
latest set (``.gazua/run.json``, ``report.html`` and ``report.md``) is replaced as one
recoverable transaction: previous files are kept as managed backups and a journal records the
publication, so an interruption is rolled back by the next command before it reads or changes
the latest set. Three replaces are never assumed to be one atomic commit.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import ValidationError

from gazua.reports.models import RUN_SCHEMA_VERSION, ExitCode, ReportDiagnostic, RunDocument
from gazua.runtime.evidence import EvidencePathError, safe_directory, write_atomic

GAZUA_FOLDER: Final = ".gazua"
RUNS_FOLDER: Final = "runs"
LATEST_FILES: Final = ("run.json", "report.html", "report.md")
MANIFEST: Final = "manifest.json"
JOURNAL: Final = ".latest-journal.json"
STAGING: Final = ".latest-staging"
BACKUP: Final = ".latest-backup"
MAX_RUN_JSON_BYTES: Final = 64 * 1024 * 1024
MAX_RUN_JSON_DEPTH: Final = 64
_RUN_ID: Final = re.compile(r"^GAZUA-run-[A-Za-z0-9-]+$")


class StorageError(Exception):
    """A storage operation failed. ``code`` is safe to print; no path or value is attached."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RunLoadError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class SaveResult:
    """What a save published, with paths relative to the project root."""

    run_id: str
    status: Literal["complete", "partial"]
    paths: dict[str, str]
    retained_runs: int
    diagnostics: list[ReportDiagnostic] = field(default_factory=list[ReportDiagnostic])
    exit_code: ExitCode = 0


def gazua_root(root: Path) -> Path:
    return root / GAZUA_FOLDER


def is_link(path: Path) -> bool:
    """A symlink, junction or other reparse point; never followed."""
    try:
        status = path.lstat()
    except FileNotFoundError:
        return False
    if path.is_symlink():
        return True
    attributes = getattr(status, "st_file_attributes", 0)
    return bool(attributes & 0x400)


def _depth(value: Any) -> int:
    deepest = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, level = stack.pop()
        deepest = max(deepest, level)
        if isinstance(item, dict):
            stack.extend((child, level + 1) for child in item.values())  # type: ignore[union-attr]
        elif isinstance(item, list):
            stack.extend((child, level + 1) for child in item)  # type: ignore[union-attr]
    return deepest


def read_run_bytes(path: Path) -> bytes:
    try:
        if is_link(path) or not path.is_file():
            raise RunLoadError("run_file_not_found")
        if path.stat().st_size > MAX_RUN_JSON_BYTES:
            raise RunLoadError("run_file_too_large")
        with path.open("rb") as handle:
            content = handle.read(MAX_RUN_JSON_BYTES + 1)
    except OSError:
        raise RunLoadError("run_file_not_found") from None
    if len(content) > MAX_RUN_JSON_BYTES:
        raise RunLoadError("run_file_too_large")
    return content


def parse_run_document(content: bytes) -> RunDocument:
    """A validated document from JSON text; references inside it are never opened."""
    try:
        data = json.loads(content.decode("utf-8"))
    except RecursionError:
        raise RunLoadError("run_file_too_deep") from None
    except (UnicodeDecodeError, ValueError):
        raise RunLoadError("run_file_invalid_json") from None
    if _depth(data) > MAX_RUN_JSON_DEPTH:
        raise RunLoadError("run_file_too_deep")
    if not isinstance(data, dict):
        raise RunLoadError("run_file_invalid")
    version = data.get("schema_version")  # type: ignore[union-attr]
    if version != RUN_SCHEMA_VERSION:
        raise RunLoadError("run_schema_version_unsupported")
    try:
        return RunDocument.model_validate_json(content)
    except ValidationError:
        raise RunLoadError("run_file_invalid") from None


def load_run_document(path: Path) -> RunDocument:
    return parse_run_document(read_run_bytes(path))


def document_json(document: RunDocument) -> str:
    return document.model_dump_json(indent=2) + "\n"


def _clear(path: Path) -> None:
    if is_link(path):
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def recover_latest(root: Path) -> bool:
    """Rolls back a publication that an interruption left half done. True when it did."""
    folder = gazua_root(root)
    journal = folder / JOURNAL
    if not journal.is_file() or is_link(journal):
        return False
    try:
        planned = json.loads(journal.read_text(encoding="utf-8")).get("files", [])
    except (OSError, ValueError, AttributeError):
        planned = list(LATEST_FILES)
    backup = folder / BACKUP
    for name in (item for item in planned if item in LATEST_FILES):
        target = folder / name
        saved = backup / name
        if saved.is_file() and not is_link(saved):
            os.replace(saved, target)
        elif target.is_file() and not is_link(target):
            target.unlink()
    for leftover in (folder / STAGING, backup):
        if leftover.exists() and not is_link(leftover):
            shutil.rmtree(leftover)
    journal.unlink()
    return True


def publish_latest(root: Path, files: Mapping[str, str]) -> None:
    """Replaces the latest set as a recoverable transaction; restores the old set on failure.

    Raises ``StorageError("latest_unavailable")`` when even the rollback failed, so the caller
    never announces an incoherent set.
    """
    folder = safe_directory(root, GAZUA_FOLDER)
    recover_latest(root)
    names = [name for name in LATEST_FILES if name in files]
    staging = folder / STAGING
    backup = folder / BACKUP
    for leftover in (staging, backup):
        if leftover.exists() or is_link(leftover):
            _clear(leftover)
    safe_directory(folder, STAGING)
    for name in names:
        write_atomic(staging / name, files[name])
    safe_directory(folder, BACKUP)
    for name in names:
        current = folder / name
        if is_link(current) or (current.exists() and not current.is_file()):
            raise StorageError("latest_path_refused")
        if current.is_file():
            shutil.copy2(current, backup / name)
    write_atomic(folder / JOURNAL, json.dumps({"version": 1, "files": names}) + "\n")
    try:
        for name in names:
            os.replace(staging / name, folder / name)
    except OSError:
        try:
            recover_latest(root)
        except OSError:
            raise StorageError("latest_unavailable") from None
        raise StorageError("latest_publish_failed") from None
    (folder / JOURNAL).unlink()
    for leftover in (staging, backup):
        with contextlib.suppress(OSError):
            shutil.rmtree(leftover)


def write_history(root: Path, document: RunDocument, html: str, markdown: str) -> Path:
    """The run's history folder with its manifest written last, as proof of completion."""
    if not _RUN_ID.fullmatch(document.run_id):
        raise StorageError("run_id_invalid")
    folder = safe_directory(root, GAZUA_FOLDER, RUNS_FOLDER, document.run_id)
    write_atomic(folder / "run.json", document_json(document))
    write_atomic(folder / "report.html", html)
    write_atomic(folder / "report.md", markdown)
    manifest = {
        "owner": "gazua",
        "version": 1,
        "run_id": document.run_id,
        "created_at": document.metadata.created_at,
        "complete": True,
    }
    write_atomic(folder / MANIFEST, json.dumps(manifest, indent=2) + "\n")
    return folder


def _relative(*parts: str) -> str:
    return "/".join(parts)


def save_run(root: Path, document: RunDocument, html: str, markdown: str) -> SaveResult:
    """History first, then the latest set that points to it, then retention.

    A failure leaves the previous latest set in place and raises ``StorageError``.
    """
    from gazua.reports.lifecycle import apply_retention

    try:
        recover_latest(root)
        write_history(root, document, html, markdown)
        publish_latest(
            root,
            {"run.json": document_json(document), "report.html": html, "report.md": markdown},
        )
    except StorageError:
        raise
    except (OSError, EvidencePathError):
        raise StorageError("report_write_failed") from None
    retained, diagnostics = apply_retention(root)
    return SaveResult(
        run_id=document.run_id,
        status="complete",
        paths={
            "json": _relative(GAZUA_FOLDER, "run.json"),
            "html": _relative(GAZUA_FOLDER, "report.html"),
            "markdown": _relative(GAZUA_FOLDER, "report.md"),
            "archive": _relative(GAZUA_FOLDER, RUNS_FOLDER, document.run_id, "run.json"),
        },
        retained_runs=retained,
        diagnostics=diagnostics,
        exit_code=2 if diagnostics else document.report_exit_code,
    )


def publish_regenerated(
    root: Path, source: Path, content: bytes, html: str, markdown: str
) -> dict[str, str]:
    """The latest set rebuilt from a document. History, manifests and retention are untouched.

    The source JSON is copied as it is; when it already is the latest ``run.json`` its content
    is not rewritten.
    """
    latest_json = gazua_root(root) / "run.json"
    files: dict[str, str] = {"report.html": html, "report.md": markdown}
    same = False
    with contextlib.suppress(OSError):
        same = latest_json.is_file() and os.path.samefile(source, latest_json)
    if not same:
        files["run.json"] = content.decode("utf-8")
    try:
        publish_latest(root, files)
    except StorageError:
        raise
    except (OSError, EvidencePathError):
        raise StorageError("report_write_failed") from None
    return {
        "json": _relative(GAZUA_FOLDER, "run.json"),
        "html": _relative(GAZUA_FOLDER, "report.html"),
        "markdown": _relative(GAZUA_FOLDER, "report.md"),
    }


def storage_ready(root: Path) -> bool:
    """Whether ``.gazua/runs`` can be created and written, checked with a managed probe."""
    try:
        folder = safe_directory(root, GAZUA_FOLDER, RUNS_FOLDER)
        write_atomic(folder / ".write-probe", "")
        (folder / ".write-probe").unlink()
    except (OSError, EvidencePathError):
        return False
    return True
