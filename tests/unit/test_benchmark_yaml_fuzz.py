"""Bounded fuzzing of the YAML data profile: data or a safe diagnostic, nothing else.

Every example is size-limited and Hypothesis runs a fixed number of them, so this is a regular
test, not an open-ended fuzzing loop.
"""

import json
import math
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from gazua.diagnostics import ConfigError, Diagnostic
from gazua.yaml_data import MAX_DEPTH, MAX_FILE_BYTES, decode_document, parse_yaml

BOUNDED = settings(max_examples=150, deadline=None)
NEWLINE = chr(10)
FRAGMENTS = st.sampled_from(
    [
        "key: value\n",
        "- item\n",
        "  nested: [1, 2]\n",
        "!!python/object/apply:os.system ['echo x']\n",
        "!custom tag\n",
        "&anchor {a: 1}\n",
        "*anchor\n",
        "<<: *anchor\n",
        "key: value\nkey: other\n",
        "{a: [b, {c: d}]}\n",
        "? complex\n: key\n",
        "--- \n",
        "...\n",
        "'unterminated\n",
        '"\\x00 escaped"\n',
        "\t tab: indent\n",
        ".nan\n",
        "2026-01-01\n",
        "0x1F\n",
        "~\n",
    ]
)
TEXT = st.one_of(
    st.lists(FRAGMENTS, max_size=12).map("".join),
    st.text(max_size=400),
    st.lists(FRAGMENTS | st.text(max_size=20), max_size=10).map("".join),
)


def plain_json(value: Any, depth: int = 0) -> bool:
    if depth > MAX_DEPTH + 1:
        return False
    if value is None or isinstance(value, bool | int | str):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, list):
        return all(plain_json(item, depth + 1) for item in value)
    if isinstance(value, dict):
        return all(
            isinstance(key, str) and plain_json(item, depth + 1) for key, item in value.items()
        )
    return False


def parsed(text: str) -> tuple[Any, list[Diagnostic]]:
    """The parsed value, or the diagnostics of a refusal; any other exception escapes."""
    try:
        value, _ = parse_yaml(text, "fuzz.yaml")
    except ConfigError as error:
        return None, list(error.diagnostics)
    return value, []


@BOUNDED
@given(text=TEXT)
def test_generated_yaml_is_data_or_safe_diagnostic(text: str) -> None:
    value, diagnostics = parsed(text)
    for diagnostic in diagnostics:
        assert diagnostic.code == "invalid_yaml"
        assert "Traceback" not in diagnostic.message
        assert "python/object" not in diagnostic.message
    if not diagnostics:
        assert plain_json(value)
        json.dumps(value)


@BOUNDED
@given(depth=st.integers(min_value=1, max_value=MAX_DEPTH * 3), flow=st.booleans())
def test_yaml_budget_bounds(depth: int, flow: bool) -> None:
    nested = "".join(f"{'  ' * i}k:{NEWLINE}" for i in range(depth))
    text = "[" * depth + "]" * depth if flow else nested
    value, diagnostics = parsed(text)
    if diagnostics:
        assert depth > MAX_DEPTH - 2
        assert [item.code for item in diagnostics] == ["invalid_yaml"]
    else:
        assert plain_json(value)


def test_oversized_content_is_refused_before_parsing() -> None:
    content = b"a: " + b"x" * MAX_FILE_BYTES
    with pytest.raises(ConfigError) as refused:
        decode_document(content, "big.yaml")
    assert "1 MiB" in refused.value.diagnostics[0].message


@BOUNDED
@given(
    tag=st.sampled_from(["!!python/name:os.system", "!!python/object/new:dict", "!x", "!!binary"]),
    alias=st.booleans(),
    duplicate=st.booleans(),
)
def test_tags_duplicates_aliases_and_deep_input(tag: str, alias: bool, duplicate: bool) -> None:
    lines = [f"first: {tag} value"]
    if alias:
        lines += ["base: &b {x: 1}", "copy: *b"]
    if duplicate:
        lines += ["first: again"]
    value, diagnostics = parsed(NEWLINE.join(lines) + NEWLINE)
    if diagnostics:
        assert [item.code for item in diagnostics] == ["invalid_yaml"]
        return
    # Accepted data never carries an object built from a tag.
    assert plain_json(value)
    assert isinstance(value, dict)
    assert isinstance(value["first"], str)
