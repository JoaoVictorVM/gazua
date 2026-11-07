import json
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from jsonschema import Draft202012Validator

import gazua
from gazua.diagnostics import ConfigError
from gazua.integration.calllog import (
    MAX_VALUE_CHARS,
    CallLog,
    log_arguments,
    to_json_value,
)
from gazua.integration.errors import GazuaBlockedError
from gazua.runtime.call_log import read_call_log
from gazua.runtime.session_models import (
    CALL_RECORD_SCHEMA_FILE,
    SESSION_SCHEMA_FILE,
    build_call_record_json_schema,
    build_session_json_schema,
    packaged_schema,
    render_call_record_json_schema,
    render_session_json_schema,
)

ReadLog = Callable[[Path], list[dict[str, Any]]]


def record(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "tool": "refund",
        "arguments": {"order": 1},
        "truncated": False,
        "actor": {"id": None, "source": "none"},
        "dry_run": True,
        "undeclared": False,
        "outcome": "returned",
        "low_fidelity": False,
        "result_type": "dict",
        "error": None,
        "block_reason": None,
        "injection": None,
    }
    data.update(overrides)
    return data


def test_appended_records_get_growing_seq(tmp_path: Path, read_log: ReadLog) -> None:
    path = tmp_path / "calls.jsonl"
    log = CallLog(path)

    assert [log.append(record(tool=name)) for name in ("a", "b", "c")] == [1, 2, 3]

    lines = read_log(path)
    assert [(line["seq"], line["tool"]) for line in lines] == [(1, "a"), (2, "b"), (3, "c")]
    assert all(line["schema_version"] == 1 for line in lines)


def test_a_new_writer_continues_after_existing_lines(tmp_path: Path) -> None:
    path = tmp_path / "calls.jsonl"
    CallLog(path).append(record())

    assert CallLog(path).append(record()) == 2


def test_missing_log_folder_blocks(tmp_path: Path) -> None:
    log = CallLog(tmp_path / "absent" / "calls.jsonl")

    with pytest.raises(GazuaBlockedError) as raised:
        log.append(record())
    with pytest.raises(GazuaBlockedError):
        log.check_writable()

    assert raised.value.reason == "call_log_unavailable"


def test_concurrent_appends_keep_unique_ordered_seq(tmp_path: Path, read_log: ReadLog) -> None:
    path = tmp_path / "calls.jsonl"
    log = CallLog(path)

    def worker() -> None:
        for _ in range(50):
            log.append(record())

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert [line["seq"] for line in read_log(path)] == list(range(1, 401))


class Opaque:
    def __repr__(self) -> str:
        return "Opaque()"


class BrokenRepr:
    def __repr__(self) -> str:
        raise RuntimeError("secret value")


def test_unserializable_and_large_values_are_converted_and_cut() -> None:
    converted, truncated = log_arguments(
        {
            "small": "ok",
            "object": Opaque(),
            "broken": BrokenRepr(),
            "nan": float("nan"),
            "keys": {1: "x"},
            "long": "x" * (MAX_VALUE_CHARS + 10),
            "nested": ["y" * MAX_VALUE_CHARS, 1],
        }
    )

    assert truncated is True
    assert converted["small"] == "ok"
    assert converted["object"] == {"$repr": "Opaque()"}
    assert converted["broken"] == {"$repr": "<BrokenRepr>"}
    assert converted["nan"] == {"$repr": "nan"}
    assert "$repr" in converted["keys"]
    assert converted["long"] == "x" * MAX_VALUE_CHARS
    assert len(converted["nested"]["$truncated"]) == MAX_VALUE_CHARS
    assert log_arguments({"a": [1, {"b": None}]}) == ({"a": [1, {"b": None}]}, False)


def test_deep_values_stop_at_a_bounded_depth() -> None:
    deep: list[object] = []
    current = deep
    for _ in range(100):
        inner: list[object] = []
        current.append(inner)
        current = inner

    assert "$repr" in json.dumps(to_json_value(deep))


def test_schemas_match_models_and_are_valid() -> None:
    assert packaged_schema(SESSION_SCHEMA_FILE) == render_session_json_schema()
    assert packaged_schema(CALL_RECORD_SCHEMA_FILE) == render_call_record_json_schema()
    Draft202012Validator.check_schema(build_session_json_schema())
    Draft202012Validator.check_schema(build_call_record_json_schema())


def test_writer_records_validate_against_the_published_schema(
    tmp_path: Path, read_log: ReadLog
) -> None:
    path = tmp_path / "calls.jsonl"
    log = CallLog(path)
    arguments, truncated = log_arguments({"value": Opaque(), "text": "z" * 5000})
    log.append(record(arguments=arguments, truncated=truncated))
    log.append(
        record(
            outcome="blocked",
            block_reason="identity_hook",
            result_type=None,
            actor={"id": "attacker-1", "source": "as_user"},
        )
    )
    log.append(
        record(
            outcome="returned",
            injection={"id": "i1", "delivered": False, "reason": "unsupported_result_type"},
        )
    )

    validator = Draft202012Validator(build_call_record_json_schema())
    for line in read_log(path):
        validator.validate(line)


json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats() | st.text(),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=8), children, max_size=4)
    ),
    max_leaves=20,
)


@settings(max_examples=150, deadline=None)
@given(
    name=st.text(min_size=1, max_size=30),
    arguments=st.dictionaries(
        st.text(max_size=20), json_values | st.builds(Opaque) | st.binary(), max_size=5
    ),
)
def test_any_name_and_arguments_are_written_and_read_back(
    tmp_path_factory: pytest.TempPathFactory, name: str, arguments: dict[str, Any]
) -> None:
    path = tmp_path_factory.mktemp("log") / "calls.jsonl"
    converted, _ = log_arguments(arguments)

    CallLog(path).append(record(tool=name, arguments=converted))

    line = json.loads(path.read_text(encoding="utf-8"))
    assert line["tool"] == name
    assert set(line["arguments"]) == set(arguments)
    Draft202012Validator(build_call_record_json_schema()).validate(line)


PRIVATE_RESULT = "result-value-that-must-stay-out-of-the-log"


def transfer(amount: int, to: str, user_id: str = "") -> dict[str, str]:
    return {"secret": PRIVATE_RESULT, "user": user_id}


def explode(value: str) -> None:
    raise ValueError(f"failed with {value}")


@pytest.fixture
def wrapper_log(start_session: Callable[..., Path], policy: Callable[..., dict[str, Any]]) -> Path:
    return start_session(
        actor={"id": "attacker-1", "role": "attacker"},
        tools={
            "transfer": policy(dry_run=False, actor_arg="user_id"),
            "explode": policy(dry_run=False),
        },
    )


def test_log_records_order_arguments_actor_and_flags(wrapper_log: Path, read_log: ReadLog) -> None:
    proxied_transfer, proxied_explode = gazua.wrap([transfer, explode])

    proxied_transfer(10, to="bob", user_id="chosen-by-the-model")
    with pytest.raises(ValueError, match="failed"):
        proxied_explode("argument")
    gazua.wrap({"unknown": transfer})["unknown"](1, "x")

    first, second, third = read_log(wrapper_log)
    assert [first["seq"], second["seq"], third["seq"]] == [1, 2, 3]
    assert first["arguments"] == {"amount": 10, "to": "bob", "user_id": "attacker-1"}
    assert first["actor"] == {"id": "attacker-1", "source": "actor_arg"}
    assert (first["dry_run"], first["outcome"], first["result_type"]) == (False, "returned", "dict")
    assert second["outcome"] == "raised"
    assert second["error"] == {"type": "ValueError"}
    assert second["actor"] == {"id": None, "source": "none"}
    assert (third["undeclared"], third["dry_run"], third["low_fidelity"]) == (True, True, True)


def test_log_never_contains_return_values_or_error_messages(
    wrapper_log: Path, read_log: ReadLog
) -> None:
    proxied_transfer, proxied_explode = gazua.wrap([transfer, explode])

    assert proxied_transfer(1, "bob")["secret"] == PRIVATE_RESULT
    with pytest.raises(ValueError, match="failed"):
        proxied_explode("argument")

    content = wrapper_log.read_text(encoding="utf-8")
    assert PRIVATE_RESULT not in content
    assert "failed with" not in content


def test_wrapper_output_validates_against_published_schemas(
    wrapper_log: Path, read_log: ReadLog
) -> None:
    proxied_transfer, proxied_explode = gazua.wrap([transfer, explode])
    proxied_transfer(1, Opaque())
    proxied_transfer(2, "x" * 10_000)
    with pytest.raises(ValueError, match="failed"):
        proxied_explode("argument")
    session = json.loads((wrapper_log.parent / "session.json").read_text(encoding="utf-8"))

    Draft202012Validator(build_session_json_schema()).validate(session)
    validator = Draft202012Validator(build_call_record_json_schema())
    lines = read_log(wrapper_log)
    for line in lines:
        validator.validate(line)
    assert lines[1]["truncated"] is True


def test_log_is_flushed_per_call_and_truncated_line_is_ignored(
    wrapper_log: Path,
) -> None:
    proxied_transfer, _ = gazua.wrap([transfer, explode])
    proxied_transfer(1, "a")
    proxied_transfer(2, "b")
    complete = read_call_log(wrapper_log)
    with wrapper_log.open("a", encoding="utf-8") as handle:
        handle.write('{"schema_version": 1, "seq": 3, "tool": "trans')

    reading = read_call_log(wrapper_log)

    assert [record.seq for record in complete.records] == [1, 2]
    assert complete.truncated_tail is False
    assert [record.arguments["amount"] for record in reading.records] == [1, 2]
    assert reading.truncated_tail is True
    assert read_call_log(wrapper_log.parent / "absent.jsonl").records == ()


@pytest.mark.parametrize(
    "content",
    [
        pytest.param('{"not": "a record"}\n', id="invalid"),
        pytest.param("{broken\n", id="malformed"),
    ],
)
def test_invalid_complete_lines_are_errors(tmp_path: Path, content: str) -> None:
    path = tmp_path / "calls.jsonl"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ConfigError) as raised:
        read_call_log(path)

    assert raised.value.diagnostics[0].code == "invalid_call_log"


def test_out_of_order_records_are_errors(tmp_path: Path) -> None:
    path = tmp_path / "calls.jsonl"
    path.write_text(
        "\n".join(json.dumps({"schema_version": 1, "seq": seq, **record()}) for seq in (2, 1))
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="out of order"):
        read_call_log(path)
