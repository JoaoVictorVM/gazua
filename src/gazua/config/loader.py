"""Reads ``gazua.yaml`` as data: the strict YAML profile first, then typed validation.

Nothing in this module imports or calls the target.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import cast

from pydantic import ValidationError
from pydantic_core import ErrorDetails

from gazua.config.diagnostics import ConfigError, Diagnostic, looks_like_secret
from gazua.config.models import SCHEMA_VERSION, GazuaConfig, ToolClass
from gazua.yaml_data import (
    MAX_DEPTH,
    MAX_FILE_BYTES,
    FieldPath,
    JsonData,
    Position,
    SourceMap,
    decode_document,
    format_path,
    parse_yaml,
    read_bounded,
    walk_strings,
)
from gazua.yaml_data import field_error as _field_error

__all__ = [
    "HTTP_TARGET_MESSAGE",
    "KEY_LIKE_VALUE_MESSAGE",
    "MAX_DEPTH",
    "MAX_FILE_BYTES",
    "LoadedConfig",
    "Position",
    "SourceMap",
    "format_path",
    "load_config",
    "load_config_text",
]

KEY_LIKE_VALUE_MESSAGE = "Canaries and fixtures must be test values; this looks like a real key."
HTTP_SCHEMES = ("http://", "https://")
HTTP_TARGET_MESSAGE = (
    "HTTP targets are not supported yet; entrypoint must be a Python reference (module:attribute)."
)

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


@dataclass(frozen=True)
class LoadedConfig:
    config: GazuaConfig
    warnings: tuple[Diagnostic, ...]
    source_map: SourceMap
    file: str


def _find_secrets(data: JsonData, file: str, source_map: SourceMap) -> list[Diagnostic]:
    return [
        _field_error(
            "suspected_secret", file, path, source_map.locate(path), KEY_LIKE_VALUE_MESSAGE
        )
        for path, text in walk_strings(data)
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
    data, source_map = parse_yaml(text, file)
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

    entrypoint = data.get("entrypoint")
    if isinstance(entrypoint, str) and entrypoint.lower().startswith(HTTP_SCHEMES):
        # The URL is only recognized here; it is never resolved or contacted.
        path = ("entrypoint",)
        raise ConfigError(
            [_field_error("http_target", file, path, source_map.locate(path), HTTP_TARGET_MESSAGE)]
        )
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
    content = read_bounded(Path(path), file, "config_io")
    return load_config_text(decode_document(content, file), file)
