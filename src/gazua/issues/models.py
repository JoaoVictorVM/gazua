"""Options, results and errors of an issue export. Nothing here touches the filesystem."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, TypeAlias

ExportStatus: TypeAlias = Literal["written", "unchanged", "empty"]

ISSUES_FOLDER: Final = "issues"
MANIFEST_OWNER: Final = "gazua-issues"
MANIFEST_VERSION: Final = 1


@dataclass(frozen=True, slots=True)
class IssueOptions:
    """What to export and how. Destination is fixed: ``.gazua/issues/<run-id>/``."""

    source: Path
    include_attack: bool = False
    overwrite: bool = False


@dataclass(frozen=True, slots=True)
class ExportResult:
    """What an export left on disk, with paths relative to the project root."""

    run_id: str
    status: ExportStatus
    count: int
    directory: str | None
    files: tuple[str, ...] = ()
    exit_code: Literal[0] = 0


@dataclass(frozen=True, slots=True)
class IssueFile:
    """One rendered issue, named only by its validated finding id."""

    name: str
    content: str


class IssueExportError(Exception):
    """An export failed. ``code`` is safe to print; no path or value is attached."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)
