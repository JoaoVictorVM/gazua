"""Reads a run document, renders one issue per finding and publishes the set locally.

The whole cycle runs under the project's lifecycle lock: the latest set is recovered before the
default source is read, and the export folder is compared and replaced without another command
in between. Exporting never reads the configuration, imports the target, starts a process or
opens a connection; the confirmation command in each issue is text, never run.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from gazua.issues.models import ExportResult, IssueExportError, IssueOptions
from gazua.issues.rendering import ISSUE_TEMPLATE_VERSION, render_issues
from gazua.issues.storage import (
    build_manifest,
    compare,
    digest,
    publish,
    recover_exports,
    relative_folder,
)
from gazua.reports.lifecycle import LifecycleLock
from gazua.reports.storage import parse_run_document, read_run_bytes, recover_latest


def export_issues(
    root: Path,
    options: IssueOptions,
    *,
    before_swap: Callable[[], None] | None = None,
) -> ExportResult:
    """Exports under the lock. Raises ``RunLoadError``, ``IssueExportError`` or ``LockBusy``."""
    with LifecycleLock(root):
        recover_latest(root)
        recover_exports(root)
        source = options.source if options.source.is_absolute() else root / options.source
        content = read_run_bytes(source)
        document = parse_run_document(content)
        if document.redaction != "masked":
            raise IssueExportError("issues_unredacted_source")
        if not document.findings:
            return ExportResult(document.run_id, "empty", 0, None)
        issues = render_issues(document, include_attack=options.include_attack)
        manifest = build_manifest(
            document.run_id,
            digest(content),
            document.guide.revision,
            ISSUE_TEMPLATE_VERSION,
            options.include_attack,
            issues,
        )
        folder = relative_folder(document.run_id)
        names = tuple(f"{folder}/{item.name}" for item in issues)
        state = compare(root, manifest, issues)
        if state == "same":
            return ExportResult(document.run_id, "unchanged", len(issues), folder, names)
        if state == "unmanaged":
            raise IssueExportError("issues_unmanaged_destination")
        if state == "managed" and not options.overwrite:
            raise IssueExportError("issues_conflict")
        publish(root, manifest, issues, before_swap=before_swap)
        return ExportResult(document.run_id, "written", len(issues), folder, names)
