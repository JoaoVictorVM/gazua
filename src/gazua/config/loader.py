"""Reads ``gazua.yaml`` as data: a strict YAML profile first, then typed validation.

Values are built here from the parser's events instead of through a PyYAML constructor. No
constructor runs, so tags cannot instantiate anything, and iteration keeps deep input from
reaching any recursive code. Nothing in this module imports or calls the target.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple, TypeAlias, cast

import yaml
from pydantic import ValidationError
from pydantic_core import ErrorDetails

from gazua.config.diagnostics import ConfigError, Diagnostic, looks_like_secret, sanitize
from gazua.config.models import SCHEMA_VERSION, GazuaConfig, ToolClass

MAX_FILE_BYTES = 1024 * 1024
MAX_DEPTH = 64
KEY_LIKE_VALUE_MESSAGE = "Canaries and fixtures must be test values; this looks like a real key."

JsonData: TypeAlias = "bool | int | float | str | list[JsonData] | dict[str, JsonData] | None"
FieldPath: TypeAlias = tuple[str | int, ...]

_INTEGER = re.compile(r"[-+]?(?:0|[1-9][0-9]*)")
_EXPONENT = r"[eE][-+]?[0-9]+"
_FLOAT = re.compile(rf"[-+]?(?:(?:[0-9]+\.[0-9]*|\.[0-9]+)(?:{_EXPONENT})?|[0-9]+{_EXPONENT})")
_NON_FINITE = re.compile(r"[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN)")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}(?:[Tt \t].*)?")

_INTEGER_LIMITS = {"max_runs", "max_tool_calls", "concurrency"}
_MESSAGES = {
    "missing": "Required field is missing.",
    "extra_forbidden": "Unknown field.",
    "dict_type": "Expected a mapping.",
    "model_type": "Expected a mapping.",
    "model_attributes_type": "Expected a mapping.",
    "list_type": "Expected a list.",
    "string_type": "Expected a string.",
    "string_too_short": "Expected a non-empty string.",
    "bool_type": "Expected true or false.",
    "int_type": "Expected an integer.",
    "float_type": "Expected a number.",
    "finite_number": "Expected a finite number.",
    "greater_than": "Expected a number greater than zero.",
    "greater_than_equal": "Expected a number that is not negative.",
}
_OWN_ERROR_TYPES = {
    "reference_syntax",
    "argument_syntax",
    "tool_name",
    "host_syntax",
    "duplicate_item",
}


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


@dataclass(frozen=True)
class LoadedConfig:
    config: GazuaConfig
    warnings: tuple[Diagnostic, ...]
    source_map: SourceMap
    file: str


def format_path(path: FieldPath) -> str:
    rendered = ""
    for part in path:
        if isinstance(part, int):
            rendered += f"[{part}]"
        else:
            rendered += f".{part}" if rendered else part
    return sanitize(rendered) or "$"


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


def _field_error(
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


def _parser_events(text: str) -> Iterator[yaml.Event]:
    loader = yaml.SafeLoader(text)
    try:
        while loader.check_event():  # pyright: ignore[reportUnknownMemberType]
            yield loader.get_event()  # pyright: ignore[reportUnknownMemberType]
    finally:
        loader.dispose()  # pyright: ignore[reportUnknownMemberType]


def _parse(text: str, file: str) -> tuple[JsonData, SourceMap]:
    builder = _DocumentBuilder()
    try:
        for event in _parser_events(text):
            builder.feed(event)
    except _Rejected as rejected:
        diagnostic = _field_error(
            "invalid_yaml", file, builder.current_path, rejected.position, rejected.message
        )
        raise ConfigError([diagnostic]) from None
    except yaml.YAMLError as error:
        # PyYAML messages can quote the document, so only the position is kept.
        diagnostic = _field_error(
            "invalid_yaml",
            file,
            builder.current_path,
            _syntax_position(error, text),
            "Invalid YAML syntax; check the indentation and quoting at this position.",
        )
        raise ConfigError([diagnostic]) from None
    return builder.root, builder.source_map


def _walk_strings(value: JsonData) -> Iterator[tuple[FieldPath, str]]:
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


def _find_secrets(data: JsonData, file: str, source_map: SourceMap) -> list[Diagnostic]:
    return [
        _field_error(
            "suspected_secret", file, path, source_map.locate(path), KEY_LIKE_VALUE_MESSAGE
        )
        for path, text in _walk_strings(data)
        if looks_like_secret(text)
    ]


def _message_for(error: ErrorDetails, path: FieldPath) -> str:
    kind = error["type"]
    if kind in _OWN_ERROR_TYPES:
        return error["msg"]
    if kind == "literal_error":
        return f"Expected one of: {error.get('ctx', {}).get('expected', 'the allowed values')}."
    if kind == "greater_than" and path and path[-1] in _INTEGER_LIMITS:
        return "Expected an integer greater than zero."
    return _MESSAGES.get(kind, "Invalid value.")


def _from_validation(error: ValidationError, file: str, source_map: SourceMap) -> list[Diagnostic]:
    by_path: dict[FieldPath, Diagnostic] = {}
    for detail in error.errors(include_input=False, include_url=False):
        path: FieldPath = tuple(detail["loc"])
        kind = detail["type"]
        if kind == "missing":
            position = source_map.locate(path[:-1])
        else:
            # Unions and key validators append labels that are not part of the document.
            while path and path not in source_map.values:
                path = path[:-1]
            key_position = source_map.keys.get(path)
            at_key = kind in ("extra_forbidden", "tool_name") and key_position is not None
            position = cast("Position", key_position) if at_key else source_map.locate(path)
        message = _message_for(detail, path)
        if path in by_path:
            message = "This value has an invalid type or format."
        by_path[path] = _field_error("invalid_field", file, path, position, message)
    return list(by_path.values())


def _relation_errors(config: GazuaConfig, file: str, source_map: SourceMap) -> list[Diagnostic]:
    errors: list[Diagnostic] = []

    def report(path: FieldPath, message: str) -> None:
        errors.append(_field_error("invalid_field", file, path, source_map.locate(path), message))

    unknown_tool = "References a tool that is not declared under tools."
    attacker, victim = config.fixtures.attacker, config.fixtures.victim
    if attacker and victim and attacker.id == victim.id:
        report(("fixtures", "victim", "id"), "Attacker and victim must have different ids.")
    for side, identity in (("attacker", attacker), ("victim", victim)):
        for index, record in enumerate(identity.records if identity else []):
            if record.tool not in config.tools:
                report(("fixtures", side, "records", index, "tool"), unknown_tool)
    for index, task in enumerate(config.legit_tasks):
        if task.expected_tool not in config.tools:
            report(("legit_tasks", index, "expected_tool"), unknown_tool)
    return errors


def _classification_warnings(
    config: GazuaConfig, file: str, source_map: SourceMap
) -> tuple[Diagnostic, ...]:
    warnings: list[Diagnostic] = []
    for name, tool in config.tools.items():
        if tool.classification is ToolClass.UNCLASSIFIED:
            position = source_map.locate(("tools", name))
            warnings.append(
                Diagnostic(
                    code="unclassified_tool",
                    severity="warning",
                    file=file,
                    line=position.line,
                    column=position.column,
                    field=format_path(("tools", name)),
                    message="No sensitive or forbidden declaration; the tool stays in dry-run.",
                )
            )
    return tuple(warnings)


def load_config_text(text: str, file: str) -> LoadedConfig:
    """Validates configuration text. ``file`` is only the label used in diagnostics."""
    data, source_map = _parse(text, file)
    if not isinstance(data, dict):
        position = source_map.values[()] if data is not None else Position(1, 1)
        message = "The top level must be a mapping."
        raise ConfigError([_field_error("invalid_yaml", file, (), position, message)])
    version = data.get("schema_version")
    if type(version) is not int or version != SCHEMA_VERSION:
        path: FieldPath = ("schema_version",)
        message = (
            f"Expected schema_version: {SCHEMA_VERSION}. "
            "Another version needs an explicit migration."
        )
        position = source_map.locate(path)
        raise ConfigError([_field_error("unsupported_version", file, path, position, message)])

    errors = _find_secrets(data, file, source_map)
    try:
        config = GazuaConfig.model_validate(data, strict=True)
    except ValidationError as error:
        errors += _from_validation(error, file, source_map)
        raise ConfigError(errors) from None
    errors += _relation_errors(config, file, source_map)
    if errors:
        raise ConfigError(errors)
    return LoadedConfig(
        config=config,
        warnings=_classification_warnings(config, file, source_map),
        source_map=source_map,
        file=file,
    )


def load_config(path: str | Path) -> LoadedConfig:
    """Loads and validates a configuration file without importing or calling the target."""
    file = str(path)
    try:
        with Path(path).open("rb") as stream:
            content = stream.read(MAX_FILE_BYTES + 1)
    except OSError as error:
        reason = error.strerror or type(error).__name__
        message = f"Could not read the file: {reason}."
        raise ConfigError([Diagnostic(code="config_io", file=file, message=message)]) from None
    start = Position(1, 1)
    if len(content) > MAX_FILE_BYTES:
        message = "The file is larger than 1 MiB."
        raise ConfigError([_field_error("invalid_yaml", file, (), start, message)])
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        message = "The file is not UTF-8."
        raise ConfigError([_field_error("invalid_yaml", file, (), start, message)]) from None
    return load_config_text(text, file)
