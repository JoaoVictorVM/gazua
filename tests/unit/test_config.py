import json
import sys
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gazua.config import (
    AbsenceResult,
    ConfigError,
    Diagnostic,
    ToolClass,
    find_absences,
    load_config,
    load_config_text,
    resolve_reference,
    tool_not_found,
)
from gazua.config.loader import MAX_DEPTH, MAX_FILE_BYTES

HEADER = "schema_version: 1\n"
REVIEWED = """\
schema_version: 1
entrypoint: tests.gazua_target:entrypoint
target:
  reset: tests.gazua_target:reset
  as_user: tests.gazua_target:as_user
tools:
  get_order:
    safe: true
    sensitive: false
    owner_arg: user_id
    actor_arg: actor_id
    dry_run_return: null
fixtures:
  attacker: {id: GAZUA-attacker}
  victim:
    id: GAZUA-victim
    records:
      - {tool: get_order, id_arg: order_id, id: GAZUA-order-1}
canaries: [GAZUA-CANARY-ONLY-TEST]
output_sink: tests.gazua_target:output_sink
legit_tasks:
  - {request: Show my test order, expected_tool: get_order}
allowed_targets: [localhost]
"""


def load(text: str):
    return load_config_text(text, "gazua.yaml")


def errors_of(text: str) -> tuple[Diagnostic, ...]:
    with pytest.raises(ConfigError) as caught:
        load(text)
    return caught.value.diagnostics


def only_error(text: str) -> Diagnostic:
    diagnostics = errors_of(text)
    assert len(diagnostics) == 1, diagnostics
    return diagnostics[0]


def test_defaults_preserve_missing_declarations() -> None:
    loaded = load(HEADER + "tools:\n  a: {}\n  b: {dry_run_return: null}\n")
    config = loaded.config

    assert config.entrypoint is None
    assert (config.limits.max_runs, config.limits.timeout) == (300, 120)
    assert (config.limits.max_tool_calls, config.limits.concurrency) == (50, 2)
    assert config.limits.max_cost is None
    assert config.limits.cost_per_run is None
    assert config.gate.fail_on == ["high", "critical"]
    assert config.allowed_targets == ["localhost", "127.0.0.1", "::1"]
    assert config.tools["a"].safe is False
    assert config.tools["a"].sensitive is None
    assert not config.tools["a"].has_dry_run_return
    assert config.tools["b"].has_dry_run_return
    assert config.tools["b"].dry_run_return is None
    assert config.to_document() == {
        "schema_version": 1,
        "tools": {"a": {}, "b": {"dry_run_return": None}},
    }


@pytest.mark.parametrize(
    ("tool", "expected"),
    [
        ("{}", ToolClass.UNCLASSIFIED),
        ("{sensitive: null, forbidden: null}", ToolClass.UNCLASSIFIED),
        ("{sensitive: false}", ToolClass.REGULAR),
        ("{forbidden: false}", ToolClass.REGULAR),
        ("{sensitive: true}", ToolClass.SENSITIVE),
        ("{forbidden: true, sensitive: true}", ToolClass.FORBIDDEN),
        ("{forbidden: true, sensitive: false}", ToolClass.FORBIDDEN),
        ("{sensitive: true, forbidden: false}", ToolClass.SENSITIVE),
    ],
)
def test_classification_is_derived_from_declarations(tool: str, expected: ToolClass) -> None:
    assert load(f"{HEADER}tools:\n  a: {tool}\n").config.tools["a"].classification is expected


def test_safe_does_not_release_an_unclassified_tool_from_dry_run() -> None:
    tools = load(
        HEADER + "tools:\n  a: {safe: true}\n  b: {safe: true, sensitive: false}\n  c: {}\n"
    ).config.tools

    assert tools["a"].requires_dry_run
    assert not tools["b"].requires_dry_run
    assert tools["c"].requires_dry_run


def test_unclassified_tool_produces_a_located_warning() -> None:
    warnings = load(HEADER + "tools:\n  a: {}\n  b: {sensitive: true}\n").warnings

    assert [item.code for item in warnings] == ["unclassified_tool"]
    assert warnings[0].severity == "warning"
    assert warnings[0].field == "tools.a"
    assert warnings[0].line == 3


@pytest.mark.parametrize(
    ("replacement", "declaration", "tool", "result"),
    [
        (
            ("    sensitive: false\n", ""),
            "sensitive, forbidden",
            "get_order",
            AbsenceResult.UNCLASSIFIED,
        ),
        (
            ("    owner_arg: user_id\n", ""),
            "owner_arg",
            "get_order",
            AbsenceResult.MISSING_OWNER,
        ),
        (
            ("    actor_arg: actor_id\n", ""),
            None,
            "get_order",
            AbsenceResult.MISSING_IDENTITY,
        ),
        (
            ("    safe: true\n", ""),
            "safe",
            "get_order",
            AbsenceResult.NOT_SAFE,
        ),
        (
            ("    dry_run_return: null\n", ""),
            "dry_run_return",
            "get_order",
            AbsenceResult.GENERIC_RETURN,
        ),
        (
            ("  attacker: {id: GAZUA-attacker}\n", ""),
            "fixtures",
            None,
            AbsenceResult.MISSING_FIXTURES,
        ),
        (
            ("canaries: [GAZUA-CANARY-ONLY-TEST]\n", ""),
            "canaries",
            None,
            AbsenceResult.MISSING_FIXTURES,
        ),
        (
            ("legit_tasks:\n  - {request: Show my test order, expected_tool: get_order}\n", ""),
            "legit_tasks",
            None,
            AbsenceResult.NO_LEGIT_TASKS,
        ),
        (
            ("output_sink: tests.gazua_target:output_sink\n", ""),
            "output_sink",
            None,
            AbsenceResult.NO_OUTPUT_SINK,
        ),
        (
            ("  reset: tests.gazua_target:reset\n", ""),
            "target.reset",
            None,
            AbsenceResult.NO_RESET,
        ),
        (
            ("allowed_targets: [localhost]\n", ""),
            "allowed_targets",
            None,
            AbsenceResult.LOCALHOST_ONLY,
        ),
    ],
    ids=[
        "classification",
        "owner_arg",
        "actor_arg",
        "safe",
        "dry_run_return",
        "fixtures",
        "canaries",
        "legit_tasks",
        "output_sink",
        "reset",
        "allowed_targets",
    ],
)
def test_missing_declaration_contract_matrix(
    replacement: tuple[str, str], declaration: str | None, tool: str | None, result: AbsenceResult
) -> None:
    assert find_absences(load(REVIEWED).config) == ()
    old, new = replacement
    assert old in REVIEWED

    absences = find_absences(load(REVIEWED.replace(old, new)).config)

    # The identity row needs both sources gone, so the hook is removed separately below.
    if declaration is None:
        assert absences == ()
        without_hook = REVIEWED.replace(old, new).replace(
            "  as_user: tests.gazua_target:as_user\n", ""
        )
        absences = find_absences(load(without_hook).config)
        declaration = "actor_arg, target.as_user"
    assert [(item.declaration, item.tool, item.result) for item in absences] == [
        (declaration, tool, result)
    ]


@pytest.mark.parametrize(
    ("result", "text"),
    [
        (AbsenceResult.NO_LEGIT_TASKS, "Legitimate use: not tested"),
        (AbsenceResult.NO_OUTPUT_SINK, "Conditional risk, not verified"),
        (AbsenceResult.MISSING_OWNER, "missing owner_arg"),
        (AbsenceResult.MISSING_IDENTITY, "missing identity"),
    ],
)
def test_absence_messages_keep_the_documented_wording(result: AbsenceResult, text: str) -> None:
    assert text in result.value


def test_explicit_empty_target_list_authorizes_nothing() -> None:
    config = load(HEADER + "allowed_targets: []\n").config

    assert config.allowed_targets == []
    assert AbsenceResult.LOCALHOST_ONLY not in [item.result for item in find_absences(config)]


def test_declared_tool_missing_from_registry_has_documented_message() -> None:
    assert tool_not_found("get_order").render() == (
        "Tool get_order is declared but was not discovered."
    )


@pytest.mark.parametrize(
    ("text", "line", "column", "field", "message"),
    [
        (
            HEADER + "limits:\n  max_runs: 0\n",
            3,
            13,
            "limits.max_runs",
            "Expected an integer greater than zero.",
        ),
        (
            HEADER + "legit_tasks:\n  - request: ok\n    expected_tool: 7\n",
            4,
            20,
            "legit_tasks[0].expected_tool",
            "Expected a string.",
        ),
        (
            HEADER + "legit_tasks:\n  - request: ok\n",
            3,
            5,
            "legit_tasks[0].expected_tool",
            "Required field is missing.",
        ),
        (
            HEADER + "limits:\n  max_runz: 1\n",
            3,
            3,
            "limits.max_runz",
            "Unknown field.",
        ),
        (
            HEADER + "tools:\n  a: {safe: false}\n  b: {saf: false}\n",
            4,
            7,
            "tools.b.saf",
            "Unknown field.",
        ),
    ],
)
def test_invalid_nested_field_reports_source_location(
    text: str, line: int, column: int, field: str, message: str
) -> None:
    diagnostic = only_error(text)

    assert (diagnostic.code, diagnostic.file) == ("invalid_field", "gazua.yaml")
    assert (diagnostic.line, diagnostic.column, diagnostic.field) == (line, column, field)
    assert diagnostic.render() == f"gazua.yaml:{line}:{column}: {field}: {message}"


@pytest.mark.parametrize(
    "text",
    ["", "---\n", "# only a comment\n", "- 1\n", "text\n"],
    ids=["empty", "null-root", "comment", "list-root", "scalar-root"],
)
def test_document_without_mapping_root_uses_root_field(text: str) -> None:
    diagnostic = only_error(text)

    assert (diagnostic.code, diagnostic.field) == ("invalid_yaml", "$")
    assert diagnostic.line == 1


@pytest.mark.parametrize(
    "text",
    ["limits: {}\n", "schema_version: 2\n", 'schema_version: "1"\n', "schema_version: true\n"],
    ids=["missing", "other", "string", "bool"],
)
def test_unsupported_version_requires_migration(text: str) -> None:
    diagnostic = only_error(text)

    assert (diagnostic.code, diagnostic.field) == ("unsupported_version", "schema_version")
    assert "migration" in diagnostic.message


@pytest.mark.parametrize(
    "fragment",
    [
        "x: !!python/object/apply:os.system [touch sentinel]\n",
        "x: !!python/name:os.system\n",
        "x: !custom value\n",
        "x: !!binary aGk=\n",
        "x: !!set {a, b}\n",
        "x: !!str text\n",
        "x: 2024-01-01\n",
        "x: 2024-01-01 10:00:00\n",
        "x: &anchor 1\n",
        "x: &anchor 1\ny: *anchor\n",
        "<<: {a: 1}\n",
        "x: 1\nx: 2\n",
        "? [a, b]\n: 1\n",
        "1: a\n",
        "true: a\n",
        "null: a\n",
        "x: .nan\n",
        "x: -.inf\n",
        "x: 1e999\n",
        "x: [unclosed\n",
        "x: 1\n---\ny: 2\n",
        "x: '\x07'\n",
    ],
)
def test_yaml_rejects_unsafe_and_ambiguous_constructs(
    fragment: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    diagnostic = errors_of(HEADER + fragment)[0]

    assert diagnostic.code == "invalid_yaml"
    assert diagnostic.line is not None
    assert list(tmp_path.iterdir()) == []


def test_syntax_error_does_not_quote_the_document() -> None:
    rendered = only_error(HEADER + 'x: "sentinel-value\n').render()

    assert "sentinel-value" not in rendered
    assert rendered.startswith("gazua.yaml:")


def test_nodes_keep_only_json_scalars() -> None:
    raw = (
        HEADER
        + "tools:\n  a:\n    dry_run_return:\n"
        + "      words: [on, off, yes, no, True, NULL, 010, 0x10, 1_000, '12']\n"
        + "      numbers: [1, -2, 1.5, 1e3, 2.0E+1]\n"
        + "      others: [true, false, null, ~, '${OPENAI_API_KEY}']\n"
    )

    value: Any = load(raw).config.tools["a"].dry_run_return

    assert value["words"] == [
        "on",
        "off",
        "yes",
        "no",
        "True",
        "NULL",
        "010",
        "0x10",
        "1_000",
        "12",
    ]
    assert value["numbers"] == [1, -2, 1.5, 1000.0, 20.0]
    assert value["others"] == [True, False, None, None, "${OPENAI_API_KEY}"]


@pytest.mark.parametrize(
    ("fragment", "field"),
    [
        ('limits: {max_runs: "3"}\n', "limits.max_runs"),
        ("limits: {max_runs: true}\n", "limits.max_runs"),
        ("limits: {max_runs: 1.5}\n", "limits.max_runs"),
        ("limits: {timeout: true}\n", "limits.timeout"),
        ("limits: {timeout: 0}\n", "limits.timeout"),
        ("limits: {cost_per_run: -1}\n", "limits.cost_per_run"),
        ('tools: {a: {safe: "false"}}\n', "tools.a.safe"),
        ("tools: {a: {safe: yes}}\n", "tools.a.safe"),
        ("tools: {a: null}\n", "tools.a"),
        ("tools: {a: {owner_arg: not-python}}\n", "tools.a.owner_arg"),
        ("tools: {a: {owner_arg: class}}\n", "tools.a.owner_arg"),
        ('tools: {"": {}}\n', "tools."),
        ('tools: {"a\\tb": {}}\n', "tools.a?b"),
        ("tools: {a: {classification: regular}}\n", "tools.a.classification"),
        ("entrypoint: os.system('x')\n", "entrypoint"),
        ("entrypoint: module\n", "entrypoint"),
        ("target: {reset: a:b:c}\n", "target.reset"),
        ("output_sink: 1\n", "output_sink"),
        ("gate: {fail_on: [huge]}\n", "gate.fail_on[0]"),
        ("gate: {fail_on: [high, high]}\n", "gate.fail_on"),
        ('canaries: [""]\n', "canaries[0]"),
        ("canaries: [a, a]\n", "canaries"),
        ('legit_tasks: [{request: "", expected_tool: a}]\n', "legit_tasks[0].request"),
        ("allowed_targets: [http://example.test]\n", "allowed_targets[0]"),
        ("allowed_targets: [example.test/path]\n", "allowed_targets[0]"),
        ("allowed_targets: ['example.test:80']\n", "allowed_targets[0]"),
        ("allowed_targets: ['*.example.test']\n", "allowed_targets[0]"),
        ("fixtures: {attacker: {records: []}}\n", "fixtures.attacker.id"),
        ("fixtures: {victim: {id: v, records: [{tool: a, id_arg: b, id: true}]}}\n", None),
        ("unknown: 1\n", "unknown"),
    ],
)
def test_strict_types_reject_coercion(fragment: str, field: str | None) -> None:
    diagnostics = errors_of(HEADER + fragment)

    assert all(item.code == "invalid_field" for item in diagnostics)
    if field is None:
        assert any(item.field == "fixtures.victim.records[0].id" for item in diagnostics)
    else:
        assert field in [item.field for item in diagnostics]


@pytest.mark.parametrize(
    ("fragment", "field"),
    [
        (
            "fixtures: {attacker: {id: same}, victim: {id: same}}\n",
            "fixtures.victim.id",
        ),
        (
            "fixtures: {victim: {id: v, records: [{tool: nope, id_arg: x, id: 1}]}}\n",
            "fixtures.victim.records[0].tool",
        ),
        (
            "legit_tasks: [{request: hi, expected_tool: nope}]\n",
            "legit_tasks[0].expected_tool",
        ),
    ],
)
def test_strict_types_and_cross_references(fragment: str, field: str) -> None:
    diagnostic = only_error(HEADER + fragment)

    assert (diagnostic.code, diagnostic.field) == ("invalid_field", field)
    assert diagnostic.line == 2


@pytest.mark.parametrize("host", ["localhost", "example.test", "127.0.0.1", "::1", "my_service"])
def test_allowed_targets_accept_exact_hosts(host: str) -> None:
    assert load(f"{HEADER}allowed_targets: ['{host}']\n").config.allowed_targets == [host]


def test_yaml_bounds_are_enforced_before_construction(tmp_path: Path) -> None:
    deep = only_error(HEADER + "x: " + "[" * 200_000)
    assert deep.code == "invalid_yaml"
    assert str(MAX_DEPTH) in deep.message

    allowed_inner = "[" * (MAX_DEPTH - 3) + "]" * (MAX_DEPTH - 3)
    accepted = HEADER + f"tools: {{a: {{dry_run_return: {allowed_inner}}}}}\n"
    assert load(accepted).config.tools["a"].has_dry_run_return

    oversized = tmp_path / "gazua.yaml"
    oversized.write_bytes(HEADER.encode() + b"#" * MAX_FILE_BYTES)
    with pytest.raises(ConfigError) as caught:
        load_config(oversized)
    assert "1 MiB" in str(caught.value)


@pytest.mark.parametrize(
    "secret",
    [
        "sk-" + "a1B2" * 10,
        "sk-ant-api03-" + "a1B2" * 10,
        "AKIA" + "ABCDEFGH23456789",
        "ghp_" + "a1B2" * 10,
        "xoxb-" + "1234567890-abcdef",
        "AIza" + "a1B2" * 9,
        "-----BEGIN RSA PRIVATE KEY-----",
        "GAZUA-" + "sk-" + "a1B2" * 10,
    ],
)
@pytest.mark.parametrize(
    "template",
    [
        "canaries: ['{}']\n",
        "fixtures: {{victim: {{id: '{}'}}}}\n",
        "tools: {{a: {{dry_run_return: {{nested: ['{}']}}}}}}\n",
        "legit_tasks: [{{request: '{}', expected_tool: a}}]\ntools: {{a: {{}}}}\n",
        "tools: {{'{}': {{}}}}\n",
    ],
    ids=["canary", "fixture", "free-value", "task", "key"],
)
def test_suspected_secret_is_never_echoed(
    secret: str, template: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(ConfigError) as caught:
        load(HEADER + template.format(secret))

    assert caught.value.diagnostics[0].code == "suspected_secret"
    assert caught.value.diagnostics[0].message == (
        "Canaries and fixtures must be test values; this looks like a real key."
    )
    captured = capsys.readouterr()
    for output in (str(caught.value), repr(caught.value.diagnostics), captured.out, captured.err):
        assert secret not in output


def test_secret_with_invalid_structure_is_not_echoed() -> None:
    secret = "sk-" + "a1B2" * 10

    diagnostics = errors_of(HEADER + f"limits: {{max_runs: '{secret}'}}\n")

    assert {item.code for item in diagnostics} == {"suspected_secret", "invalid_field"}
    assert secret not in "\n".join(item.render() for item in diagnostics)


def test_invalid_values_are_not_echoed() -> None:
    marker = "sentinel-private-value"

    for fragment in (
        f"limits: {{max_runs: {marker}}}\n",
        f"gate: {{fail_on: [{marker}]}}\n",
        f"entrypoint: {marker}\n",
        f"allowed_targets: [{marker}/x]\n",
    ):
        assert marker not in "\n".join(item.render() for item in errors_of(HEADER + fragment))


def test_printed_names_have_no_control_characters() -> None:
    rendered = only_error(HEADER + 'tools: {a: {"bad\\u001b[31m": 1}}\n').render()

    assert "\x1b" not in rendered
    assert "bad?[31m" in rendered


def test_missing_file_reports_config_io(tmp_path: Path) -> None:
    missing = tmp_path / "gazua.yaml"

    with pytest.raises(ConfigError) as caught:
        load_config(missing)

    assert caught.value.diagnostics[0].code == "config_io"
    assert str(missing) in str(caught.value)


def test_load_config_reads_utf8_file(tmp_path: Path) -> None:
    path = tmp_path / "gazua.yaml"
    path.write_bytes(b"\xef\xbb\xbf" + HEADER.encode() + "canaries: [GAZUA-ação]\n".encode())

    loaded = load_config(path)

    assert loaded.config.canaries == ["GAZUA-ação"]
    assert loaded.file == str(path)

    path.write_bytes(HEADER.encode() + b"canaries: [\xff]\n")
    with pytest.raises(ConfigError, match="not UTF-8"):
        load_config(path)


SENTINEL_MODULE = """\
import pathlib
pathlib.Path({marker!r}).write_text("imported")

def hook():
    return "called"

VALUE = 1
"""


@pytest.fixture
def sentinel_module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    marker = tmp_path / "imported.txt"
    name = "gazua_sentinel_target"
    (tmp_path / f"{name}.py").write_text(
        SENTINEL_MODULE.format(marker=str(marker)), encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    yield name, marker
    sys.modules.pop(name, None)


def test_reference_resolution_is_explicit(
    sentinel_module: tuple[str, Path], tmp_path: Path
) -> None:
    name, marker = sentinel_module
    config_path = tmp_path / "gazua.yaml"
    config_path.write_text(
        f"{HEADER}entrypoint: {name}:hook\ntarget: {{reset: {name}:hook}}\n", encoding="utf-8"
    )

    loaded = load_config(config_path)

    assert loaded.config.entrypoint == f"{name}:hook"
    assert not marker.exists()
    assert name not in sys.modules

    resolved = resolve_reference(f"{name}:hook", "entrypoint")

    assert marker.exists()
    assert resolved() == "called"


def test_reference_failures_are_reported_without_details(
    sentinel_module: tuple[str, Path],
) -> None:
    name, _ = sentinel_module

    with pytest.raises(ConfigError) as not_callable:
        resolve_reference(f"{name}:VALUE", "entrypoint")
    assert not_callable.value.diagnostics[0].code == "reference_not_callable"

    with pytest.raises(ConfigError) as missing_attribute:
        resolve_reference(f"{name}:absent", "entrypoint")
    assert missing_attribute.value.diagnostics[0].code == "reference_import"

    with pytest.raises(ConfigError) as missing_module:
        resolve_reference("gazua_module_that_does_not_exist:x", "target.reset")
    assert missing_module.value.diagnostics[0].code == "reference_import"
    assert "gazua_module_that_does_not_exist" in str(missing_module.value)
    assert missing_module.value.diagnostics[0].field == "target.reset"

    with pytest.raises(ConfigError) as invalid:
        resolve_reference("os.system('x')", "entrypoint")
    assert invalid.value.diagnostics[0].code == "invalid_field"


def test_import_error_message_does_not_leak_target_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    name = "gazua_raising_target"
    (tmp_path / f"{name}.py").write_text(
        "raise RuntimeError('sentinel-private-value')\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(tmp_path))

    with pytest.raises(ConfigError) as caught:
        resolve_reference(f"{name}:x", "entrypoint")

    assert "RuntimeError" in str(caught.value)
    assert "sentinel-private-value" not in str(caught.value)


def test_reference_resolution_survives_system_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    name = "gazua_exiting_target"
    (tmp_path / f"{name}.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))

    with pytest.raises(ConfigError, match="SystemExit"):
        resolve_reference(f"{name}:x", "entrypoint")


json_text = st.text(
    alphabet=st.characters(categories=("L", "N"), exclude_characters="\x85\u2028\u2029"),
    max_size=12,
)
json_values = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**53), max_value=2**53)
    | st.floats(allow_nan=False, allow_infinity=False, width=64)
    | json_text,
    lambda children: (
        st.lists(children, max_size=3) | st.dictionaries(json_text, children, max_size=3)
    ),
    max_leaves=8,
)
optional_flags = st.sampled_from([None, True, False, "absent"])


@given(
    value=json_values,
    has_return=st.booleans(),
    safe=st.sampled_from([True, False, "absent"]),
    sensitive=optional_flags,
    forbidden=optional_flags,
)
def test_json_roundtrip_preserves_safety_semantics(
    value: Any, has_return: bool, safe: Any, sensitive: Any, forbidden: Any
) -> None:
    tool: dict[str, Any] = {}
    for name, flag in (("safe", safe), ("sensitive", sensitive), ("forbidden", forbidden)):
        if flag != "absent":
            tool[name] = flag
    if has_return:
        tool["dry_run_return"] = value
    document = {"schema_version": 1, "tools": {"a": tool}}

    first = load(json.dumps(document, ensure_ascii=False))
    second = load(json.dumps(first.config.to_document(), ensure_ascii=False))

    assert first.config.to_document() == document
    assert second.config.to_document() == document
    assert second.config.tools["a"].has_dry_run_return is has_return
    assert second.config.tools["a"].classification is first.config.tools["a"].classification
