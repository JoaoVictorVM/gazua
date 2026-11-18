from typing import Any

import pytest

from gazua.mcp.evidence import normalize_result, to_call_result


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (
            {"content": [{"type": "text", "text": "x"}], "structuredContent": {"id": "o"}},
            {"id": "o"},
        ),
        ({"content": [{"type": "text", "text": "only"}]}, "only"),
        (
            {"content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]},
            ["a", "b"],
        ),
        ({"content": [{"type": "text", "text": '{"id": "o"}'}]}, '{"id": "o"}'),
        ({"content": []}, []),
    ],
    ids=["structured", "one_text", "many_texts", "json_text_stays_text", "empty"],
)
def test_structured_text_mixed_and_error_results(result: dict[str, Any], expected: Any) -> None:
    assert normalize_result(result) == expected


def test_mixed_content_stays_typed_and_undecoded() -> None:
    blocks = [
        {"type": "text", "text": "first"},
        {"type": "image", "data": "AAAA", "mimeType": "image/png"},
        {"type": "resource_link", "uri": "https://example.test/x", "name": "x"},
    ]

    value = normalize_result({"content": blocks})

    assert value == {"content": blocks}
    assert to_call_result(value)["content"] == blocks


@pytest.mark.parametrize(
    ("value", "content", "structured"),
    [
        ("ok", [{"type": "text", "text": "ok"}], None),
        ({"a": 1}, [{"type": "text", "text": '{"a":1}'}], {"a": 1}),
        (["a", "b"], [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}], None),
        (None, [{"type": "text", "text": "null"}], None),
        (3, [{"type": "text", "text": "3"}], None),
        (True, [{"type": "text", "text": "true"}], None),
    ],
)
def test_dry_run_values_become_results(value: Any, content: Any, structured: Any) -> None:
    result = to_call_result(value)

    assert result["content"] == content
    assert result.get("structuredContent") == structured
    assert result["isError"] is False


def test_error_result_is_not_a_success() -> None:
    from gazua.mcp.evidence import McpToolError

    error = McpToolError({"content": [{"type": "text", "text": "denied"}], "isError": True})

    assert error.result["isError"] is True
    assert "denied" not in str(error)
