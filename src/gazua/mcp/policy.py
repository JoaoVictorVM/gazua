"""What Gazua lets reach an MCP server: supported schemas and validated arguments.

Permission comes only from ``gazua.yaml``: annotations such as ``readOnlyHint`` and anything
else the server says are data, never a reason to call a tool for real. Schemas are validated
locally; a reference to another document is never fetched, from the network or from disk.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final, cast

from gazua.config.models import GazuaConfig, Tool

SCHEMA_UNSUPPORTED: Final = "mcp_schema_unsupported"
_REFERENCE_KEYS: Final = ("$ref", "$dynamicRef", "$recursiveRef")
_KNOWN_DIALECTS: Final = frozenset(
    {
        "https://json-schema.org/draft/2020-12/schema",
        "http://json-schema.org/draft-07/schema#",
        "http://json-schema.org/draft-07/schema",
    }
)
_MAX_DEPTH: Final = 64


def _external_reference(value: object, depth: int = 0) -> bool:
    if depth > _MAX_DEPTH:
        return True
    if isinstance(value, dict):
        node = cast("dict[str, object]", value)
        for key in _REFERENCE_KEYS:
            reference = node.get(key)
            if reference is not None and (
                not isinstance(reference, str) or not reference.startswith("#")
            ):
                return True
        return any(_external_reference(item, depth + 1) for item in node.values())
    if isinstance(value, list):
        return any(_external_reference(item, depth + 1) for item in cast("list[object]", value))
    return False


def schema_problem(schema: Mapping[str, Any]) -> str | None:
    """Why Gazua cannot validate arguments for this input schema; None when it can.

    The root must describe an object, and references may only point inside the same document.
    """
    if schema.get("type") != "object":
        return SCHEMA_UNSUPPORTED
    dialect = schema.get("$schema")
    if dialect is not None and dialect not in _KNOWN_DIALECTS:
        return SCHEMA_UNSUPPORTED
    if _external_reference(dict(schema)):
        return SCHEMA_UNSUPPORTED
    properties = schema.get("properties", {})
    required = schema.get("required", [])
    if not isinstance(properties, dict) or not isinstance(required, list):
        return SCHEMA_UNSUPPORTED
    if not all(isinstance(item, str) for item in cast("list[object]", required)):
        return SCHEMA_UNSUPPORTED
    return None


def arguments_valid(schema: Mapping[str, Any], arguments: Mapping[str, Any]) -> bool:
    """Whether the arguments satisfy the schema, checked without leaving this process.

    Any reference the local document does not hold fails validation instead of being loaded.
    """
    if schema_problem(schema) is not None:
        return False
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
    from referencing.exceptions import NoSuchResource

    def refuse(uri: str) -> Resource[Any]:
        raise NoSuchResource(ref=uri)

    try:
        validator: Any = Draft202012Validator(dict(schema), registry=Registry(retrieve=refuse))
        return not any(True for _ in validator.iter_errors(dict(arguments)))
    # The schema is the server's data: any failure to validate it refuses the call.
    except Exception:  # noqa: BLE001
        return False


def forwarding_allowed(config: GazuaConfig, name: str, approved: Mapping[str, str] | None) -> bool:
    """Whether a call may reach the server at all: declared, classified, ``safe: true``, known.

    A tool that the approved snapshot did not have stays in dry-run for the whole run, even
    when a declaration with that name says it is safe.
    """
    declaration: Tool | None = config.tools.get(name)
    if declaration is None or declaration.requires_dry_run:
        return False
    return approved is None or name in approved
