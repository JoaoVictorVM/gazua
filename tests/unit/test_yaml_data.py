from pathlib import Path

import pytest

import gazua.config
import gazua.config.loader
from gazua import yaml_data
from gazua.config import ConfigError, load_config_text
from gazua.diagnostics import ConfigError as SharedConfigError
from gazua.diagnostics import Diagnostic as SharedDiagnostic
from gazua.yaml_data import (
    MAX_DEPTH,
    MAX_FILE_BYTES,
    Position,
    SourceMap,
    decode_document,
    parse_yaml,
    read_bounded,
)


def rejection(text: str) -> SharedDiagnostic:
    with pytest.raises(ConfigError) as caught:
        parse_yaml(text, "mold.yaml")
    (diagnostic,) = caught.value.diagnostics
    return diagnostic


def test_config_profile_survives_parser_extraction() -> None:
    assert gazua.config.SourceMap is SourceMap
    assert gazua.config.loader.SourceMap is SourceMap
    assert gazua.config.ConfigError is SharedConfigError
    assert gazua.config.Diagnostic is SharedDiagnostic
    assert (gazua.config.loader.MAX_DEPTH, gazua.config.loader.MAX_FILE_BYTES) == (
        MAX_DEPTH,
        MAX_FILE_BYTES,
    )

    loaded = load_config_text("schema_version: 1\ntools:\n  a: {safe: true}\n", "gazua.yaml")
    assert loaded.source_map.locate(("tools", "a", "safe")) == Position(3, 13)
    assert loaded.source_map.keys[("tools", "a")] == Position(3, 3)

    data, source_map = parse_yaml("a:\n  - 1\n  - 2.5\n  - 'x'\n  - null\n", "m.yaml")
    assert data == {"a": [1, 2.5, "x", None]}
    assert source_map.locate(("a", 2)) == Position(4, 5)


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("a: !!python/object/apply:os.system ['echo executed > SENTINEL']\n", "tags"),
        ("a: !custom value\n", "tags"),
        ("a: &x 1\nb: *x\n", "aliases"),
        ("base: {a: 1}\nc:\n  <<: {a: 1}\n", "merge"),
        ("a: 1\na: 2\n", "repeated"),
        ("a: 1\n---\nb: 2\n", "one YAML document"),
        ("a: 2024-01-01\n", "Dates"),
        ("a: .inf\n", "finite"),
    ],
)
def test_yaml_tags_aliases_merges_and_duplicate_keys_are_rejected(
    text: str, fragment: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    diagnostic = rejection(text)

    assert diagnostic.code == "invalid_yaml"
    assert fragment in diagnostic.message
    assert diagnostic.line is not None
    assert diagnostic.column is not None
    assert "echo" not in diagnostic.render()
    assert list(tmp_path.iterdir()) == []


def test_bounded_read_and_depth_are_enforced(tmp_path: Path) -> None:
    deep = rejection("a: " + "[" * 200_000)
    assert str(MAX_DEPTH) in deep.message

    inner = MAX_DEPTH - 1
    data, _ = parse_yaml("[" * inner + "]" * inner, "m.yaml")
    assert isinstance(data, list)

    oversized = tmp_path / "big.yaml"
    oversized.write_bytes(b"#" * (MAX_FILE_BYTES * 4))
    content = read_bounded(oversized, "big.yaml", "catalog_io")
    assert len(content) == MAX_FILE_BYTES + 1
    with pytest.raises(ConfigError) as caught:
        decode_document(content, "big.yaml")
    assert "1 MiB" in str(caught.value)

    with pytest.raises(ConfigError) as missing:
        read_bounded(tmp_path / "absent.yaml", "absent.yaml", "catalog_io")
    assert missing.value.diagnostics[0].code == "catalog_io"

    with pytest.raises(ConfigError) as not_utf8:
        decode_document(b"a: \xff\n", "latin.yaml")
    assert "UTF-8" in str(not_utf8.value)


def test_strings_are_walked_with_paths() -> None:
    data, _ = parse_yaml("a: [x, {b: y}]\n", "m.yaml")

    assert sorted(yaml_data.walk_strings(data)) == [
        (("a",), "a"),
        (("a", 0), "x"),
        (("a", 1, "b"), "b"),
        (("a", 1, "b"), "y"),
    ]
