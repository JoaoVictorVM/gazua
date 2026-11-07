"""Strict YAML data profile shared by ``gazua.yaml`` and attack molds.

Values are built here from the parser's events instead of through a PyYAML constructor. No
constructor runs, so tags cannot instantiate anything, and iteration keeps deep input from
reaching any recursive code. The result is plain JSON data plus the position of every value.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple, TypeAlias, cast

import yaml

from gazua.diagnostics import ConfigError, Diagnostic, sanitize

MAX_FILE_BYTES = 1024 * 1024
MAX_DEPTH = 64

JsonData: TypeAlias = "bool | int | float | str | list[JsonData] | dict[str, JsonData] | None"
FieldPath: TypeAlias = tuple[str | int, ...]

_INTEGER = re.compile(r"[-+]?(?:0|[1-9][0-9]*)")
_EXPONENT = r"[eE][-+]?[0-9]+"
_FLOAT = re.compile(rf"[-+]?(?:(?:[0-9]+\.[0-9]*|\.[0-9]+)(?:{_EXPONENT})?|[0-9]+{_EXPONENT})")
_NON_FINITE = re.compile(r"[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN)")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}(?:[Tt \t].*)?")


class Position(NamedTuple):
    line: int
    column: int


@dataclass(frozen=True)
class SourceMap:
    """Where each value and each mapping key came from, by path of keys and indexes."""

    values: dict[FieldPath, Position] = field(default_factory=dict[FieldPath, Position])
    keys: dict[FieldPath, Position] = field(default_factory=dict[FieldPath, Position])

    def locate(self, path: FieldPath) -> Position:
        """Position of the path, or of its closest declared ancestor."""
        current = path
        while current:
            if current in self.values:
                return self.values[current]
            current = current[:-1]
        return self.values.get((), Position(1, 1))


def format_path(path: FieldPath) -> str:
    rendered = ""
    for part in path:
        if isinstance(part, int):
            rendered += f"[{part}]"
        else:
            rendered += f".{part}" if rendered else part
    return sanitize(rendered) or "$"


def field_error(
    code: str, file: str, path: FieldPath, position: Position, message: str
) -> Diagnostic:
    return Diagnostic(
        code=code,
        file=file,
        line=position.line,
        column=position.column,
        field=format_path(path),
        message=message,
    )


class _Rejected(Exception):
    def __init__(self, message: str, position: Position) -> None:
        super().__init__(message)
        self.message = message
        self.position = position


def _position(mark: yaml.Mark) -> Position:
    return Position(mark.line + 1, mark.column + 1)


def _plain_scalar(text: str, position: Position) -> JsonData:
    if text in ("", "~", "null"):
        return None
    if text in ("true", "false"):
        return text == "true"
    if _TIMESTAMP.fullmatch(text):
        raise _Rejected("Dates are not supported; quote the value to use text.", position)
    if _NON_FINITE.fullmatch(text):
        raise _Rejected("Expected a finite number.", position)
    try:
        if _INTEGER.fullmatch(text):
            return int(text)
        if _FLOAT.fullmatch(text):
            number = float(text)
            if not math.isfinite(number):
                raise _Rejected("Expected a finite number.", position)
            return number
    except ValueError:
        raise _Rejected("This number is too large.", position) from None
    return text


class _Frame:
    def __init__(self, container: list[JsonData] | dict[str, JsonData], path: FieldPath) -> None:
        self.container = container
        self.path = path
        self.pending_key: str | None = None

    @property
    def awaiting_key(self) -> bool:
        return isinstance(self.container, dict) and self.pending_key is None


class _DocumentBuilder:
    def __init__(self) -> None:
        self.source_map = SourceMap()
        self.stack: list[_Frame] = []
        self.root: JsonData = None
        self.documents = 0

    @property
    def current_path(self) -> FieldPath:
        if not self.stack:
            return ()
        frame = self.stack[-1]
        return (*frame.path, frame.pending_key) if frame.pending_key is not None else frame.path

    def feed(self, event: yaml.Event) -> None:
        position = _position(event.start_mark)
        if isinstance(event, yaml.DocumentStartEvent):
            self.documents += 1
            if self.documents > 1:
                raise _Rejected("Only one YAML document is allowed.", position)
        elif isinstance(event, yaml.AliasEvent):
            raise _Rejected("YAML aliases and anchors are not allowed.", position)
        elif isinstance(event, yaml.ScalarEvent):
            self._check_node(event.anchor, event.tag, position)
            self._scalar(event, position)
        elif isinstance(event, yaml.MappingStartEvent | yaml.SequenceStartEvent):
            self._check_node(event.anchor, event.tag, position)
            self._open(event, position)
        elif isinstance(event, yaml.MappingEndEvent | yaml.SequenceEndEvent):
            self.stack.pop()

    def _check_node(self, anchor: str | None, tag: str | None, position: Position) -> None:
        if anchor is not None:
            raise _Rejected("YAML aliases and anchors are not allowed.", position)
        if tag is not None:
            raise _Rejected("YAML tags are not allowed.", position)

    def _scalar(self, event: yaml.ScalarEvent, position: Position) -> None:
        plain = event.style is None
        if self.stack and self.stack[-1].awaiting_key:
            self._key(self.stack[-1], event.value, plain, position)
            return
        self._attach(_plain_scalar(event.value, position) if plain else event.value, position)

    def _key(self, frame: _Frame, text: str, plain: bool, position: Position) -> None:
        if plain and text == "<<":
            raise _Rejected("YAML merge keys are not allowed.", position)
        if plain and not isinstance(_plain_scalar(text, position), str):
            raise _Rejected("Mapping keys must be strings.", position)
        if text in frame.container:
            raise _Rejected("This key is repeated in the same mapping.", position)
        frame.pending_key = text
        self.source_map.keys[(*frame.path, text)] = position

    def _open(self, event: yaml.Event, position: Position) -> None:
        if len(self.stack) >= MAX_DEPTH:
            raise _Rejected(f"Nesting is limited to {MAX_DEPTH} levels.", position)
        if self.stack and self.stack[-1].awaiting_key:
            raise _Rejected("Mapping keys must be strings.", position)
        container: list[JsonData] | dict[str, JsonData] = (
            {} if isinstance(event, yaml.MappingStartEvent) else []
        )
        path = self._next_value_path()
        self._attach(container, position)
        self.stack.append(_Frame(container, path))

    def _next_value_path(self) -> FieldPath:
        if not self.stack:
            return ()
        frame = self.stack[-1]
        if isinstance(frame.container, list):
            return (*frame.path, len(frame.container))
        return (*frame.path, cast("str", frame.pending_key))

    def _attach(self, value: JsonData, position: Position) -> None:
        self.source_map.values[self._next_value_path()] = position
        if not self.stack:
            self.root = value
            return
        frame = self.stack[-1]
        if isinstance(frame.container, list):
            frame.container.append(value)
        else:
            frame.container[cast("str", frame.pending_key)] = value
            frame.pending_key = None


def _syntax_position(error: yaml.YAMLError, text: str) -> Position:
    if isinstance(error, yaml.MarkedYAMLError) and error.problem_mark is not None:
        return _position(error.problem_mark)
    if isinstance(error, yaml.reader.ReaderError) and isinstance(error.position, int):
        before = text[: error.position]
        return Position(before.count("\n") + 1, error.position - before.rfind("\n"))
    return Position(1, 1)


def _parser_events(text: str) -> Iterator[yaml.Event]:
    loader = yaml.SafeLoader(text)
    try:
        while loader.check_event():  # pyright: ignore[reportUnknownMemberType]
            yield loader.get_event()  # pyright: ignore[reportUnknownMemberType]
    finally:
        loader.dispose()  # pyright: ignore[reportUnknownMemberType]


def parse_yaml(text: str, file: str) -> tuple[JsonData, SourceMap]:
    """Parses one YAML document as JSON data. ``file`` is only the label used in diagnostics."""
    builder = _DocumentBuilder()
    try:
        for event in _parser_events(text):
            builder.feed(event)
    except _Rejected as rejected:
        diagnostic = field_error(
            "invalid_yaml", file, builder.current_path, rejected.position, rejected.message
        )
        raise ConfigError([diagnostic]) from None
    except yaml.YAMLError as error:
        # PyYAML messages can quote the document, so only the position is kept.
        diagnostic = field_error(
            "invalid_yaml",
            file,
            builder.current_path,
            _syntax_position(error, text),
            "Invalid YAML syntax; check the indentation and quoting at this position.",
        )
        raise ConfigError([diagnostic]) from None
    return builder.root, builder.source_map


def walk_strings(value: JsonData) -> Iterator[tuple[FieldPath, str]]:
    """Every string in the data, mapping keys included, with its path."""
    stack: list[tuple[JsonData, FieldPath]] = [(value, ())]
    while stack:
        current, where = stack.pop()
        if isinstance(current, str):
            yield where, current
        elif isinstance(current, list):
            stack.extend((item, (*where, index)) for index, item in enumerate(current))
        elif isinstance(current, dict):
            for key, item in current.items():
                yield (*where, key), key
                stack.append((item, (*where, key)))


def decode_document(content: bytes, file: str) -> str:
    """Checks the size limit and the encoding of content read with :func:`read_bounded`."""
    start = Position(1, 1)
    if len(content) > MAX_FILE_BYTES:
        message = "The file is larger than 1 MiB."
        raise ConfigError([field_error("invalid_yaml", file, (), start, message)])
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError:
        message = "The file is not UTF-8."
        raise ConfigError([field_error("invalid_yaml", file, (), start, message)]) from None


def read_bounded(path: Path, file: str, io_code: str) -> bytes:
    """Reads at most one byte past the limit, so an oversized file is never fully loaded."""
    try:
        with path.open("rb") as stream:
            return stream.read(MAX_FILE_BYTES + 1)
    except OSError as error:
        reason = error.strerror or type(error).__name__
        message = f"Could not read the file: {reason}."
        raise ConfigError([Diagnostic(code=io_code, file=file, message=message)]) from None
