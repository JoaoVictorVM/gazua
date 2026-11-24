import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from gazua.config.loader import load_config_text
from gazua.config.models import build_json_schema
from gazua.diagnostics import ConfigError

TYPESCRIPT = {
    "module": "dist/gazua-test.js",
    "entrypoint_export": "respond",
    "reset_export": "reset",
    "as_user_export": "asUser",
    "output_sink_export": "observeOutput",
}


def load(**fields: Any) -> Any:
    document = {"schema_version": 1, **fields}
    return load_config_text(json.dumps(document), "gazua.yaml").config


def messages(**fields: Any) -> list[str]:
    with pytest.raises(ConfigError) as caught:
        load(**fields)
    return [item.message for item in caught.value.diagnostics]


def test_adapter_is_strict_exclusive_and_schema_backed(project_root: Path) -> None:
    config = load(typescript=TYPESCRIPT, tools={"get_order": {"safe": True, "sensitive": False}})
    assert config.typescript.module == "dist/gazua-test.js"
    assert (config.has_reset, config.has_as_user, config.has_output_sink) == (True, True, True)
    minimal = load(typescript={"module": "a.mjs", "entrypoint_export": "$respond"})
    assert (minimal.has_reset, minimal.has_as_user, minimal.has_output_sink) == (False,) * 3

    assert messages(typescript={**TYPESCRIPT, "command": "node"})
    for module in ("../a.js", "/abs/a.js", "src/a.ts", "C:/a.js", "a\\b.js", "a.js?x", "a//b.js"):
        assert messages(typescript={**TYPESCRIPT, "module": module}), module
    assert messages(typescript={**TYPESCRIPT, "entrypoint_export": "not-valid"})

    for other, value in (
        ("entrypoint", "agent:respond"),
        ("mcp", {"transport": "stdio", "command": "node"}),
        ("http", {"endpoint": "http://localhost:8000/agent"}),
    ):
        found = messages(typescript=TYPESCRIPT, **{other: value})
        assert any(f"typescript and {other} are different targets" in text for text in found)
    hooks = messages(
        typescript=TYPESCRIPT,
        target={"reset": "hooks:reset", "as_user": "hooks:as_user"},
        output_sink="hooks:sink",
    )
    assert sum("cannot reach a TypeScript target" in text for text in hooks) == 3

    schema = build_json_schema()
    packaged = json.loads(
        (project_root / "src/gazua/schemas/config-v1.schema.json").read_text("utf-8")
    )
    assert packaged == schema
    validator = jsonschema.Draft202012Validator(schema)
    assert not list(validator.iter_errors({"schema_version": 1, "typescript": TYPESCRIPT}))
    for module in ("../a.js", "src/a.ts"):
        bad = {"schema_version": 1, "typescript": {**TYPESCRIPT, "module": module}}
        assert list(validator.iter_errors(bad)), module
