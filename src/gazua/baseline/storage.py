"""Reads, merges and replaces the baseline file without ever losing the previous bytes.

Reading is bounded and strict: size, depth and cardinality limits, no duplicate JSON keys, no
NaN or Infinity, no extra fields. A rejected file is never treated as empty. Writing goes to an
exclusive temporary file in the same folder, is validated and synced, and replaces the file
only if it still holds the bytes that were read; a conflict is refused, never overwritten.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import secrets
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast

from pydantic import TypeAdapter, ValidationError

from gazua.baseline.models import (
    BASELINE_SCHEMA_VERSION,
    MAX_ENTRIES,
    MAX_SCENARIO_REFERENCES,
    BaselineDocument,
    BaselineEntry,
    PackageVersion,
    ScenarioReference,
    baseline_json,
    ordered_references,
    scenario_digest,
)

if TYPE_CHECKING:
    from gazua.reports.models import RunDocument, Scenario

MAX_BASELINE_BYTES: Final = 8 * 1024 * 1024
MAX_BASELINE_DEPTH: Final = 16
RESERVED_FOLDER: Final = ".gazua"

MESSAGES: Final = {
    "baseline_missing": ("No baseline at this path. Create one with gazua baseline after a run."),
    "baseline_invalid": (
        "The baseline is not valid; it was not used as empty. Restore it from version control."
    ),
    "baseline_version_unsupported": (
        "The baseline uses a format version this Gazua cannot read. Install a Gazua that reads "
        "it, or follow the documented migration when one exists."
    ),
    "baseline_limit_exceeded": (
        "The baseline exceeds the size, depth or entry limits; it was not used."
    ),
    "baseline_path_invalid": (
        "The baseline must be a regular file inside the project, outside .gazua/, and not the "
        "configuration file."
    ),
    "baseline_conflict": (
        "The baseline changed since it was read; nothing was overwritten. Run the command again."
    ),
    "baseline_write_failed": ("The baseline could not be written; the previous file was kept."),
    "baseline_source_incomplete": (
        "This run.json comes from an interrupted run or one with operational errors; it cannot "
        "be accepted as a baseline."
    ),
}


class BaselineError(Exception):
    """A baseline problem. ``code`` and ``field`` are safe to print; no value is attached."""

    def __init__(self, code: str, field: str | None = None) -> None:
        self.code = code
        self.field = field
        super().__init__(code)

    @property
    def message(self) -> str:
        return MESSAGES.get(self.code, "The baseline cannot be used.")


@dataclass(frozen=True, slots=True)
class LoadedBaseline:
    """A validated baseline with the exact bytes it was read from and their digest."""

    path: Path
    document: BaselineDocument
    content: bytes

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


def _is_link(path: Path) -> bool:
    try:
        status = path.lstat()
    except FileNotFoundError:
        return False
    if path.is_symlink():
        return True
    return bool(getattr(status, "st_file_attributes", 0) & 0x400)


def resolve_baseline_path(root: Path, path: Path, *, config_path: Path | None = None) -> Path:
    """The baseline path inside the project, checked before anything is read or written.

    Relative paths start at the project root. Links, junctions, folders, anything under
    ``.gazua/`` and the configuration file itself are refused.
    """
    base = Path(os.path.abspath(root))
    candidate = Path(os.path.abspath(path if path.is_absolute() else base / path))
    try:
        relative = candidate.relative_to(base)
    except ValueError:
        raise BaselineError("baseline_path_invalid") from None
    parts = relative.parts
    if not parts or parts[0].lower() == RESERVED_FOLDER:
        raise BaselineError("baseline_path_invalid")
    current = base
    for part in parts:
        current = current / part
        if _is_link(current):
            raise BaselineError("baseline_path_invalid")
    if config_path is not None:
        configured = Path(os.path.abspath(config_path))
        if os.path.normcase(str(configured)) == os.path.normcase(str(candidate)):
            raise BaselineError("baseline_path_invalid")
    if candidate.exists() and not candidate.is_file():
        raise BaselineError("baseline_path_invalid")
    return candidate


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    found: dict[str, Any] = {}
    for key, value in pairs:
        if key in found:
            raise BaselineError("baseline_invalid", "duplicate_key")
        found[key] = value
    return found


def _reject_constant(name: str) -> Any:
    raise BaselineError("baseline_invalid", "non_finite_number")


def _depth(value: Any) -> int:
    deepest = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, level = stack.pop()
        deepest = max(deepest, level)
        if level > MAX_BASELINE_DEPTH:
            return level
        if isinstance(item, dict):
            stack.extend((child, level + 1) for child in item.values())  # type: ignore[union-attr]
        elif isinstance(item, list):
            stack.extend((child, level + 1) for child in item)  # type: ignore[union-attr]
    return deepest


def _cardinality(data: dict[str, Any]) -> None:
    entries = data.get("entries")
    if not isinstance(entries, list):
        return
    if len(entries) > MAX_ENTRIES:  # type: ignore[arg-type]
        raise BaselineError("baseline_limit_exceeded", "entries")
    total = 0
    for entry in entries:  # type: ignore[union-attr]
        if isinstance(entry, dict):
            scenarios = entry.get("scenarios")  # type: ignore[union-attr]
            if isinstance(scenarios, list):
                total += len(scenarios)  # type: ignore[arg-type]
    if total > MAX_SCENARIO_REFERENCES:
        raise BaselineError("baseline_limit_exceeded", "scenarios")


def parse_baseline(content: bytes) -> BaselineDocument:
    """A validated baseline from its bytes; raises ``BaselineError`` with a printable code."""
    if len(content) > MAX_BASELINE_BYTES:
        raise BaselineError("baseline_limit_exceeded", "size")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise BaselineError("baseline_invalid", "encoding") from None
    try:
        data = json.loads(
            text, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant
        )
    except RecursionError:
        raise BaselineError("baseline_limit_exceeded", "depth") from None
    except ValueError:
        raise BaselineError("baseline_invalid", "json") from None
    if _depth(data) > MAX_BASELINE_DEPTH:
        raise BaselineError("baseline_limit_exceeded", "depth")
    if not isinstance(data, dict):
        raise BaselineError("baseline_invalid", "document")
    document = cast("dict[str, Any]", data)
    version: object = document.get("schema_version")
    if type(version) is not int:
        raise BaselineError("baseline_invalid", "schema_version")
    if version != BASELINE_SCHEMA_VERSION:
        raise BaselineError("baseline_version_unsupported", "schema_version")
    _cardinality(document)
    try:
        return BaselineDocument.model_validate(document)
    except ValidationError as error:
        first = error.errors()[0]["loc"] if error.errors() else ()
        field = ".".join(str(item) for item in first if isinstance(item, str)) or None
        raise BaselineError("baseline_invalid", field) from None


def read_baseline(path: Path) -> LoadedBaseline:
    """The baseline at an already resolved path; ``baseline_missing`` when there is none."""
    if _is_link(path):
        raise BaselineError("baseline_path_invalid")
    try:
        if not path.exists():
            raise BaselineError("baseline_missing")
        if not path.is_file():
            raise BaselineError("baseline_path_invalid")
        if path.stat().st_size > MAX_BASELINE_BYTES:
            raise BaselineError("baseline_limit_exceeded", "size")
        with path.open("rb") as handle:
            content = handle.read(MAX_BASELINE_BYTES + 1)
    except OSError:
        raise BaselineError("baseline_invalid", "read") from None
    return LoadedBaseline(path=path, document=parse_baseline(content), content=content)


def _current_bytes(path: Path) -> bytes | None:
    if _is_link(path):
        raise BaselineError("baseline_path_invalid")
    if not path.exists():
        return None
    with path.open("rb") as handle:
        return handle.read(MAX_BASELINE_BYTES + 1)


def write_baseline(
    path: Path,
    document: BaselineDocument,
    expected: bytes | None,
    *,
    before_replace: Callable[[], None] | None = None,
) -> bytes:
    """Replaces the baseline atomically when it still holds ``expected`` (None: absent).

    The previous bytes survive any failure before the replace; only the temporary file this
    call created is removed. ``before_replace`` runs right before the replace, for tests.
    """
    content = baseline_json(document).encode("utf-8")
    if parse_baseline(content) != document:
        raise BaselineError("baseline_write_failed")
    temporary = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
    created = False
    try:
        descriptor = os.open(
            temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o644
        )
        created = True
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if _current_bytes(path) != expected:
            raise BaselineError("baseline_conflict")
        if before_replace is not None:
            before_replace()
        os.replace(temporary, path)
        created = False
    except BaselineError:
        raise
    except OSError:
        raise BaselineError("baseline_write_failed") from None
    finally:
        if created:
            with contextlib.suppress(OSError):
                temporary.unlink()
    return content


@dataclass(frozen=True, slots=True)
class AcceptedFinding:
    """One finding of a report as the merge sees it: id, mode and the group's scenarios."""

    id: str
    mode: str
    scenarios: tuple[ScenarioReference, ...]


@dataclass(frozen=True, slots=True)
class MergeOutcome:
    """The merged document and what changed. ``changed`` false means nothing to write."""

    document: BaselineDocument
    created: bool
    changed: bool
    accepted: int
    preserved: int
    reopened: int


def merge_findings(
    existing: BaselineDocument | None,
    findings: Sequence[AcceptedFinding],
    gazua_version: str | None,
) -> MergeOutcome:
    """Accepts the findings as open and keeps every entry the report does not mention.

    Nothing is closed by absence. A finding that was closed and is accepted again is reopened
    and loses its receipt. Coverage only grows. An unchanged result keeps the old revision.
    """
    entries = {item.id: item for item in (existing.entries if existing else [])}
    reopened = 0
    seen: set[str] = set()
    for finding in findings:
        seen.add(finding.id)
        previous = entries.get(finding.id)
        references = list(finding.scenarios)
        if previous is not None:
            references.extend(previous.scenarios)
            if previous.status == "closed":
                reopened += 1
        entries[finding.id] = BaselineEntry.model_validate(
            {
                "id": finding.id,
                "mode": finding.mode,
                "status": "open",
                "scenarios": [item.model_dump() for item in ordered_references(references)],
                "verification": None,
            }
        )
    ordered = [entries[key] for key in sorted(entries)]
    changed = existing is None or ordered != list(existing.entries)
    if not changed and existing is not None:
        document = existing
    else:
        document = BaselineDocument(
            schema_version=1,
            gazua_version=package_version(gazua_version),
            revision=1 if existing is None else existing.revision + 1,
            entries=ordered,
        )
    preserved = sum(1 for key in entries if key not in seen)
    return MergeOutcome(
        document=document,
        created=existing is None,
        changed=changed,
        accepted=len(seen),
        preserved=preserved,
        reopened=reopened,
    )


def package_version(value: str | None) -> str | None:
    """The installed version when it fits the baseline's version pattern; else None."""
    if value is None:
        return None
    try:
        return TypeAdapter(PackageVersion).validate_python(value)
    except ValidationError:
        return None


def source_problems(document: RunDocument) -> list[str]:
    """Why a report cannot be accepted: an interruption or any operational error."""
    problems: list[str] = []
    if document.report_exit_code == 2:
        problems.append("exit_code")
    if document.engine.interrupted:
        problems.append("interrupted")
    if document.verdicts.operational_errors or document.engine.operational_errors:
        problems.append("operational_errors")
    if any(item.level == "error" for item in document.diagnostics):
        problems.append("report_errors")
    return problems


def untested_scenarios(document: RunDocument) -> int:
    """Scenarios the report did not test; a baseline made from it does not certify them."""
    return sum(1 for item in document.verdicts.results if item.state == "not_tested")


def accepted_findings(document: RunDocument) -> list[AcceptedFinding]:
    """Each finding with every scenario of its mode, mold and tool in the report, proven or not.

    The covered scenarios are the group's, so a later verification must test them all again.
    """
    results = {item.attack_key: item for item in document.verdicts.results}
    accepted: list[AcceptedFinding] = []
    for finding in document.findings:
        group = [
            scenario_reference(document, item)
            for item in document.scenarios
            if item.mold_id == finding.mold_id
            and item.tool_name == finding.tool_name
            and results[item.attack_key].mode == finding.mode
        ]
        accepted.append(AcceptedFinding(finding.id, finding.mode, tuple(ordered_references(group))))
    return accepted


def scenario_reference(document: RunDocument, scenario: Scenario) -> ScenarioReference:
    """The scenario's reference: its digest and the run's language."""
    return ScenarioReference(
        scenario_digest=scenario_digest(scenario.attack_key),
        language=document.metadata.language,
    )


@dataclass(frozen=True, slots=True)
class AcceptResult:
    """What ``gazua baseline`` did, as data: counts, revision and the exit code."""

    created: bool
    changed: bool
    accepted: int
    preserved: int
    reopened: int
    revision: int
    untested: int
    exit_code: int = 0


def accept_report(output: Path, document: RunDocument, gazua_version: str | None) -> AcceptResult:
    """Merges the report's findings into the baseline at ``output``, which is resolved.

    A missing file is created; an invalid one is an error and is never replaced. A merge that
    changes nothing writes nothing, so the file's bytes and revision stay as they were.
    """
    if source_problems(document):
        raise BaselineError("baseline_source_incomplete")
    loaded: LoadedBaseline | None
    try:
        loaded = read_baseline(output)
    except BaselineError as error:
        if error.code != "baseline_missing":
            raise
        loaded = None
    merged = merge_findings(
        None if loaded is None else loaded.document,
        accepted_findings(document),
        gazua_version,
    )
    if merged.changed:
        write_baseline(output, merged.document, None if loaded is None else loaded.content)
    return AcceptResult(
        created=merged.created,
        changed=merged.changed,
        accepted=merged.accepted,
        preserved=merged.preserved,
        reopened=merged.reopened,
        revision=merged.document.revision,
        untested=untested_scenarios(document),
    )


__all__ = [
    "MAX_BASELINE_BYTES",
    "MAX_BASELINE_DEPTH",
    "MESSAGES",
    "AcceptResult",
    "AcceptedFinding",
    "BaselineError",
    "LoadedBaseline",
    "MergeOutcome",
    "accept_report",
    "accepted_findings",
    "merge_findings",
    "package_version",
    "parse_baseline",
    "read_baseline",
    "resolve_baseline_path",
    "scenario_reference",
    "source_problems",
    "untested_scenarios",
    "write_baseline",
]
