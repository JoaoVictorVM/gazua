"""Loads molds from the package and from configured local folders, as data only.

Nothing here imports the target, calls tools, reads the environment or opens connections.
Folders outside the package are third-party content: a warning is reported before each one is
read, links are never followed and every file passes the same strict validation as the
packaged molds.
"""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Any, Final, Literal, TypeAlias, cast, get_args

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from pydantic_core import ErrorDetails

from gazua.catalog.models import (
    ID_PATTERN,
    MOLD_SCHEMA_VERSION,
    Mold,
    MoldId,
    Requirement,
)
from gazua.config.models import GazuaConfig
from gazua.diagnostics import ConfigError, Diagnostic, sanitize
from gazua.yaml_data import (
    FieldPath,
    Position,
    SourceMap,
    decode_document,
    field_error,
    parse_yaml,
    read_bounded,
)

Origin: TypeAlias = Literal["builtin", "custom", "external"]
Release: TypeAlias = Literal["v0.1", "v0.2", "v0.4"]
RELEASES: tuple[Release, ...] = get_args(Release)

MAX_SOURCE_FILES: Final = 1000
MAX_SOURCE_BYTES: Final = 16 * 1024 * 1024
MAX_CATALOG_MOLDS: Final = 2000
EXTERNAL_WARNING: Final = (
    "Warning: loading external attack catalog {path}. "
    "Review its content; attack text may reach the model provider."
)
BUILTIN_LABEL: Final = "builtin"

_URL_LIKE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_REPARSE_POINT = 0x400
_MOLD_SUFFIXES = (".yaml", ".yml")
_CODES = {
    "exfiltration_domain": "invalid_exfiltration_domain",
    "mold_binding": "invalid_mold_binding",
}
_MESSAGES = {
    "missing": "Required field is missing.",
    "extra_forbidden": "Unknown field.",
    "dict_type": "Expected a mapping.",
    "model_type": "Expected a mapping.",
    "model_attributes_type": "Expected a mapping.",
    "list_type": "Expected a list.",
    "string_type": "Expected a string.",
    "string_too_short": "Expected a non-empty string.",
    "string_too_long": "This text is too long.",
    "too_short": "Expected a non-empty list.",
    "too_long": "This list has too many items.",
    "string_pattern_mismatch": (
        "Expected lowercase letters, digits and hyphens, starting with a letter."
    ),
    "union_tag_invalid": "Unknown action kind.",
    "union_tag_not_found": "The action needs a kind.",
}


class MoldError(ConfigError):
    """Diagnostics of one mold file, with the label that names the mold in messages."""

    def __init__(self, diagnostics: list[Diagnostic], mold: str) -> None:
        super().__init__(diagnostics)
        self.mold = mold


@dataclass(frozen=True)
class LoadedMold:
    mold: Mold
    source_map: SourceMap
    file: str


@dataclass(frozen=True)
class CatalogEntry:
    """A valid mold and where it came from. Provenance is never read from the mold itself."""

    mold: Mold
    origin: Origin
    source: str
    file: str
    introduced_in: Release | None = None

    @property
    def id(self) -> str:
        return self.mold.id

    @property
    def requirements(self) -> tuple[Requirement, ...]:
        return self.mold.effective_requirements


@dataclass(frozen=True)
class MoldDiagnostic:
    """An error about one mold or one source. ``mold`` is the sanitized id or file name."""

    diagnostic: Diagnostic
    mold: str | None = None

    def render(self) -> str:
        if self.mold is None:
            return self.diagnostic.render()
        return f"invalid mold {sanitize(self.mold)}: {self.diagnostic.render()}"


@dataclass(frozen=True)
class CatalogLoadResult:
    entries: tuple[CatalogEntry, ...]
    diagnostics: tuple[MoldDiagnostic, ...]
    warnings: tuple[Diagnostic, ...]
    release: Release
    has_errors: bool

    @property
    def molds(self) -> tuple[Mold, ...]:
        return tuple(entry.mold for entry in self.entries)

    def summary(self) -> dict[str, Any]:
        """Serializable view without attack text."""
        return {
            "molds": [
                {
                    "id": entry.id,
                    "mode": list(entry.mold.modes),
                    "severity": entry.mold.effective_severity,
                    "origin": entry.origin,
                }
                for entry in self.entries
            ],
            "warnings": [{"code": item.code, "file": item.file} for item in self.warnings],
            "diagnostics": [
                {
                    "code": item.diagnostic.code,
                    "file": item.diagnostic.file,
                    "line": item.diagnostic.line,
                    "column": item.diagnostic.column,
                    "field": item.diagnostic.field,
                    "message": item.diagnostic.message,
                }
                for item in self.diagnostics
            ],
            "has_errors": self.has_errors,
        }


def _mold_label(data: object, file: str) -> str:
    if isinstance(data, dict):
        identifier = cast("dict[str, object]", data).get("id")
        if isinstance(identifier, str) and re.fullmatch(ID_PATTERN, identifier):
            return identifier
    return Path(file).name


def _document_path(location: tuple[int | str, ...]) -> FieldPath:
    """The location without the labels that the action unions add to pydantic errors."""
    if not location or location[0] != "action" or len(location) < 2:
        return location
    tag, rest = location[1], location[2:]
    if tag == "tools":
        return ("action", *rest[1:])
    if tag == "dual" and rest[:1] == ("tools",):
        return ("action", "tools", *rest[2:])
    return ("action", *rest)


def _message_for(error: ErrorDetails) -> str:
    kind = error["type"]
    if kind in ("mold_relation", "duplicate_item", "invalid_text", "opaque_payload") or (
        kind in _CODES
    ):
        return error["msg"]
    if kind == "literal_error":
        return f"Expected one of: {error.get('ctx', {}).get('expected', 'the allowed values')}."
    return _MESSAGES.get(kind, "Invalid value.")


def _from_validation(error: ValidationError, file: str, source_map: SourceMap) -> list[Diagnostic]:
    by_path: dict[FieldPath, Diagnostic] = {}
    for detail in error.errors(include_input=False, include_url=False):
        kind = detail["type"]
        if kind == "mold_relation":
            path = cast("FieldPath", detail.get("ctx", {}).get("path", ()))
        else:
            path = _document_path(tuple(detail["loc"]))
        key_position = source_map.keys.get(path)
        if kind == "missing":
            position = source_map.locate(path[:-1])
        elif kind == "extra_forbidden" and key_position is not None:
            position = key_position
        else:
            position = source_map.locate(path)
        code = _CODES.get(kind, "invalid_field")
        message = _message_for(detail)
        if path in by_path and by_path[path].code == code:
            message = "This value has an invalid type or format."
        by_path[path] = field_error(code, file, path, position, message)
    return list(by_path.values())


def load_mold_text(text: str, file: str) -> LoadedMold:
    """Validates one mold. ``file`` is only the label used in diagnostics. Nothing runs."""
    try:
        data, source_map = parse_yaml(text, file)
    except ConfigError as error:
        raise MoldError(list(error.diagnostics), Path(file).name) from None
    label = _mold_label(data, file)
    if not isinstance(data, dict):
        position = source_map.values.get((), Position(1, 1))
        message = "The top level must be a mapping."
        raise MoldError([field_error("invalid_yaml", file, (), position, message)], label)
    version = data.get("schema_version")
    if type(version) is not int or version != MOLD_SCHEMA_VERSION:
        path: FieldPath = ("schema_version",)
        message = (
            f"Expected schema_version: {MOLD_SCHEMA_VERSION}. "
            "Another version needs an explicit migration."
        )
        position = source_map.locate(path)
        raise MoldError([field_error("unsupported_version", file, path, position, message)], label)
    try:
        mold = Mold.model_validate(data, strict=True)
    except ValidationError as error:
        raise MoldError(_from_validation(error, file, source_map), label) from None
    return LoadedMold(mold=mold, source_map=source_map, file=file)


class _ManifestItem(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    id: MoldId
    file: str = Field(pattern=r"^[a-z][a-z0-9-]{0,79}\.yaml$")
    introduced_in: Release


class _Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: Literal[1]
    catalog_release: Release
    molds: list[_ManifestItem]


@dataclass
class _Collector:
    entries: list[CatalogEntry] = field(default_factory=list[CatalogEntry])
    diagnostics: list[MoldDiagnostic] = field(default_factory=list[MoldDiagnostic])
    warnings: list[Diagnostic] = field(default_factory=list[Diagnostic])
    errors: bool = False

    def fail(self, diagnostic: Diagnostic, mold: str | None = None) -> None:
        self.diagnostics.append(MoldDiagnostic(diagnostic, mold))
        self.errors = True


def _integrity(message: str) -> Diagnostic:
    return Diagnostic(
        code="catalog_integrity",
        file=f"{BUILTIN_LABEL}/manifest.json",
        message=f"The packaged catalog is inconsistent: {message} Reinstall Gazua.",
    )


def release_order(release: Release) -> int:
    return RELEASES.index(release)


def packaged_manifest() -> dict[str, Any]:
    folder = files("gazua").joinpath("catalog/builtin")
    return json.loads(folder.joinpath("manifest.json").read_text(encoding="utf-8"))


def _load_builtin(collector: _Collector, release: Release | None) -> Release:
    folder = files("gazua").joinpath("catalog/builtin")
    try:
        manifest = _Manifest.model_validate(packaged_manifest(), strict=True)
    except (OSError, ValueError):
        collector.fail(_integrity("the manifest is missing or invalid."))
        return release or RELEASES[0]
    chosen = release or manifest.catalog_release
    ids = [item.id for item in manifest.molds]
    names = [item.file for item in manifest.molds]
    if len(set(ids)) != len(ids) or len(set(names)) != len(names):
        collector.fail(_integrity("the manifest repeats a mold id or file."))
        return chosen
    for item in manifest.molds:
        if release_order(item.introduced_in) > release_order(chosen):
            continue
        label = f"{BUILTIN_LABEL}/{item.file}"
        try:
            content = folder.joinpath(item.file).read_bytes()
            loaded = load_mold_text(decode_document(content, label), label)
        except OSError:
            collector.fail(_integrity(f"{item.file} is missing."), item.id)
            continue
        except ConfigError as error:
            for diagnostic in error.diagnostics:
                collector.fail(diagnostic, item.id)
            continue
        if loaded.mold.id != item.id:
            collector.fail(_integrity(f"{item.file} does not define {item.id}."), item.id)
            continue
        collector.entries.append(
            CatalogEntry(loaded.mold, "builtin", BUILTIN_LABEL, label, item.introduced_in)
        )
    return chosen


def _is_link(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & _REPARSE_POINT)


def _source_problem(raw: str, path: Path) -> str | None:
    if _URL_LIKE.match(raw):
        return "URLs are not accepted; download and review the catalog, then use a local folder."
    if raw.startswith(("\\\\", "//")):
        return "Network paths are not accepted; use a local folder."
    try:
        info = path.lstat()
    except OSError:
        return "The folder does not exist."
    if _is_link(info):
        return "Links are not followed; point to the real folder."
    if not stat.S_ISDIR(info.st_mode):
        return "Expected a folder."
    return None


def _candidates(path: Path) -> list[os.DirEntry[str]] | None:
    found: list[os.DirEntry[str]] = []
    with os.scandir(path) as listing:
        for entry in listing:
            if entry.name.lower().endswith(_MOLD_SUFFIXES):
                found.append(entry)
                if len(found) > MAX_SOURCE_FILES:
                    return None
    return sorted(found, key=lambda entry: entry.name)


def _read_source(
    collector: _Collector, raw: str, path: Path, origin: Origin
) -> Iterator[tuple[str, bytes]]:
    label = sanitize(raw)

    def fail(message: str, file: str = label, mold: str | None = None) -> None:
        collector.fail(Diagnostic(code="catalog_io", file=file, message=message), mold)

    try:
        candidates = _candidates(path)
    except OSError as error:
        fail(f"Could not read the folder: {error.strerror or type(error).__name__}.")
        return
    if candidates is None:
        fail(f"The folder has more than {MAX_SOURCE_FILES} mold files.")
        return
    total = 0
    for entry in candidates:
        file = str(Path(raw) / entry.name)
        try:
            info = entry.stat(follow_symlinks=False)
        except OSError:
            fail("Could not read the file.", file, entry.name)
            continue
        if _is_link(info) or not stat.S_ISREG(info.st_mode):
            fail("Links and special files are not read.", file, entry.name)
            continue
        try:
            content = read_bounded(Path(entry.path), file, "catalog_io")
        except ConfigError as error:
            for diagnostic in error.diagnostics:
                collector.fail(diagnostic, entry.name)
            continue
        total += len(content)
        if total > MAX_SOURCE_BYTES:
            fail(f"The {origin} folder holds more than 16 MiB of molds; the rest was not read.")
            return
        yield file, content


def _load_folder(
    collector: _Collector,
    raw: str,
    base: Path,
    origin: Origin,
    seen: set[Path],
    on_warning: Callable[[Diagnostic], None] | None,
) -> None:
    warning = Diagnostic(
        code="external_catalog",
        severity="warning",
        file=sanitize(raw),
        message=EXTERNAL_WARNING.format(path=sanitize(raw)),
    )
    collector.warnings.append(warning)
    if on_warning is not None:
        on_warning(warning)
    path = Path(raw)
    if not path.is_absolute() and not _URL_LIKE.match(raw):
        path = base / path
    problem = _source_problem(raw, path)
    if problem is not None:
        collector.fail(Diagnostic(code="catalog_io", file=sanitize(raw), message=problem))
        return
    resolved = path.resolve()
    if resolved in seen:
        return
    seen.add(resolved)
    for file, content in _read_source(collector, raw, path, origin):
        try:
            loaded = load_mold_text(decode_document(content, file), file)
        except ConfigError as error:
            mold = error.mold if isinstance(error, MoldError) else Path(file).name
            for diagnostic in error.diagnostics:
                collector.fail(diagnostic, mold)
            continue
        collector.entries.append(CatalogEntry(loaded.mold, origin, sanitize(raw), file))


def _reject_collisions(collector: _Collector) -> list[CatalogEntry]:
    builtin = {entry.id for entry in collector.entries if entry.origin == "builtin"}
    others: dict[str, list[CatalogEntry]] = {}
    for entry in collector.entries:
        if entry.origin != "builtin":
            others.setdefault(entry.id, []).append(entry)
    rejected: set[int] = set()
    for identifier, group in others.items():
        if identifier in builtin:
            message = "This id belongs to a packaged mold; choose another id."
        elif len(group) > 1:
            message = "Several files define this id; no definition is used. Rename them."
        else:
            continue
        for entry in group:
            rejected.add(id(entry))
            diagnostic = Diagnostic(
                code="duplicate_mold_id", file=entry.file, field="id", message=message
            )
            collector.fail(diagnostic, identifier)
    return [entry for entry in collector.entries if id(entry) not in rejected]


def load_catalog(
    config: GazuaConfig | None = None,
    *,
    config_dir: Path | None = None,
    release: Release | None = None,
    on_warning: Callable[[Diagnostic], None] | None = None,
) -> CatalogLoadResult:
    """Loads the packaged molds of a release plus the folders declared in ``config``.

    Relative folders are resolved against ``config_dir``, the folder of ``gazua.yaml``.
    ``on_warning`` is called before each third-party folder is read. Invalid files are left
    out, the remaining molds are kept and ``has_errors`` stays true.
    """
    collector = _Collector()
    chosen = _load_builtin(collector, release)
    if config is not None:
        base = config_dir if config_dir is not None else Path()
        seen: set[Path] = set()
        sources: list[tuple[str, Origin]] = [
            *((raw, "custom") for raw in config.molds.directories),
            *((raw, "external") for raw in config.molds.external_catalogs),
        ]
        for raw, origin in sources:
            _load_folder(collector, raw, base, origin, seen, on_warning)
    entries = _reject_collisions(collector)
    if len(entries) > MAX_CATALOG_MOLDS:
        message = f"The catalog has more than {MAX_CATALOG_MOLDS} molds; the rest was not used."
        collector.fail(Diagnostic(code="catalog_io", message=message))
        entries = entries[:MAX_CATALOG_MOLDS]
    if not entries:
        collector.fail(Diagnostic(code="catalog_io", message="The catalog has no valid molds."))
    return CatalogLoadResult(
        entries=tuple(entries),
        diagnostics=tuple(collector.diagnostics),
        warnings=tuple(collector.warnings),
        release=chosen,
        has_errors=collector.errors,
    )
