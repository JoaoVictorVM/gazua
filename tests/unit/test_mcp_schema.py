import builtins
import socket
import urllib.request
from typing import Any

import pytest
from mcp_support import require_mcp

from gazua.mcp.policy import arguments_valid, schema_problem

LOCAL: dict[str, Any] = {
    "type": "object",
    "$defs": {"id": {"type": "string", "minLength": 3}},
    "properties": {"order_id": {"$ref": "#/$defs/id"}, "count": {"type": "integer"}},
    "required": ["order_id"],
    "additionalProperties": False,
}


def test_local_references_validate() -> None:
    require_mcp()

    assert schema_problem(LOCAL) is None
    assert arguments_valid(LOCAL, {"order_id": "abc", "count": 2})
    assert not arguments_valid(LOCAL, {"order_id": "ab"})
    assert not arguments_valid(LOCAL, {"count": 2})
    assert not arguments_valid(LOCAL, {"order_id": "abc", "extra": 1})


@pytest.mark.parametrize(
    "schema",
    [
        {"type": "object", "properties": {"a": {"$ref": "https://example.test/a.json"}}},
        {"type": "object", "properties": {"a": {"$ref": "file:///etc/passwd"}}},
        {"type": "object", "properties": {"a": {"$ref": "other.json#/x"}}},
        {
            "type": "object",
            "$defs": {"b": {"$ref": "https://example.test/b.json"}},
            "properties": {"a": {"$ref": "#/$defs/b"}},
        },
        {"type": "object", "properties": {"a": {"$dynamicRef": "https://example.test/c"}}},
        {"type": "array"},
        {"properties": {}},
        {"type": "object", "$schema": "https://example.test/dialect"},
    ],
)
def test_external_refs_never_access_network_or_files(
    schema: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    require_mcp()
    touched: list[str] = []

    def refuse(*args: Any, **kwargs: Any) -> Any:
        touched.append(str(args[0]) if args else "call")
        raise AssertionError("no access expected")

    original_open = builtins.open
    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)

    def guarded_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        if "passwd" in str(file) or "example" in str(file):
            touched.append(str(file))
        return original_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", guarded_open)

    assert schema_problem(schema) is not None
    assert not arguments_valid(schema, {"a": "x"})
    assert touched == []


def test_unresolvable_local_reference_fails_closed() -> None:
    require_mcp()
    schema = {"type": "object", "properties": {"a": {"$ref": "#/$defs/missing"}}}

    assert not arguments_valid(schema, {"a": "x"})
