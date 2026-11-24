import json
from pathlib import Path
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from gazua.typescript.models import (
    MAX_LINE_BYTES,
    ProtocolViolation,
    RunnerInvoke,
    decode,
    encode,
    parse_line,
)

CORPUS = (
    Path(__file__).resolve().parents[2] / "packages/typescript/test/fixtures/protocol-corpus.json"
)


def accepted(direction: Any, line: bytes) -> bool:
    try:
        decode(direction, line)
    except ProtocolViolation:
        return False
    return True


def test_python_and_npm_accept_the_same_protocol_corpus() -> None:
    cases = json.loads(CORPUS.read_text(encoding="utf-8"))
    assert len(cases) > 20
    assert {item["direction"] for item in cases} == {"to_runner", "to_python"}
    for item in cases:
        assert accepted(item["direction"], item["line"].encode("utf-8")) is item["valid"], item
    # Lines the corpus cannot hold as text.
    assert not accepted("to_python", b'{"protocol_version":1,"type":"closed","request_id":"\xff"}')
    assert not accepted("to_python", b"x" * (MAX_LINE_BYTES + 1))


json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=8),
    lambda inner: (
        st.lists(inner, max_size=3) | st.dictionaries(st.text(max_size=4), inner, max_size=3)
    ),
    max_leaves=12,
)


@settings(max_examples=150, deadline=None)
@given(message=st.text(max_size=200), armed=st.none() | st.text(min_size=1, max_size=40))
def test_every_encoded_request_decodes_to_itself(message: str, armed: str | None) -> None:
    sent = RunnerInvoke(
        protocol_version=1,
        type="invoke",
        request_id="7",
        message=message,
        armed_injection_id=armed,
    )
    line = encode(sent)
    assert line.endswith(b"\n")
    assert line.count(b"\n") == 1
    assert decode("to_runner", line[:-1]) == sent


@settings(max_examples=150, deadline=None)
@given(value=json_values, cut=st.integers(min_value=1, max_value=40))
def test_truncated_or_extra_lines_never_decode(value: Any, cut: int) -> None:
    line = json.dumps(
        {"protocol_version": 1, "type": "result", "request_id": "2", "response": "ok", "x": value}
    ).encode("utf-8")
    assert not accepted("to_python", line)
    whole = json.dumps(
        {"protocol_version": 1, "type": "result", "request_id": "2", "response": "ok"}
    ).encode("utf-8")
    assert accepted("to_python", whole)
    assert not accepted("to_python", whole[: max(0, len(whole) - cut)])


@settings(max_examples=60, deadline=None)
@given(depth=st.integers(min_value=0, max_value=60))
def test_depth_limit_is_exact(depth: int) -> None:
    value: Any = "leaf"
    for _ in range(depth):
        value = [value]
    line = json.dumps({"protocol_version": 1, "type": "sink", "request_id": "3", "value": value})
    try:
        parse_line(line.encode("utf-8"))
        parsed = True
    except ProtocolViolation:
        parsed = False
    # The outer object is level zero; each list adds one level, and level 32 is refused.
    assert parsed is (depth < 32)
