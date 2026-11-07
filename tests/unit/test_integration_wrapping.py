import asyncio
import inspect
from collections import OrderedDict
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

import gazua
from gazua.discovery import discover_tools
from gazua.integration.errors import UnsupportedToolError
from gazua.integration.proxy import is_proxy
from gazua.integration.registry import registry

StartSession = Callable[..., Path]
Policy = Callable[..., dict[str, Any]]
ReadLog = Callable[[Path], list[dict[str, Any]]]


def lookup_order(order_id: int, *, verbose: bool = False) -> dict[str, Any]:
    """Reads one order."""
    return {"order": order_id, "verbose": verbose}


def refund_order(order_id: int) -> str:
    return f"refunded {order_id}"


async def fetch_page(url: str) -> str:
    """Fetches one page."""
    await asyncio.sleep(0)
    return f"page {url}"


@dataclass
class FrameworkTool:
    name: str
    func: Callable[..., Any] | None
    coroutine: Callable[..., Any] | None = None
    description: str = "framework tool"


@pytest.fixture
def agent_session(start_session: StartSession, policy: Policy) -> Path:
    return start_session(
        tools={
            "lookup_order": policy(dry_run=False),
            "refund_order": policy(has_dry_run_return=True, dry_run_return={"status": "ok"}),
            "fetch_page": policy(dry_run=False),
        }
    )


def test_wrap_accepts_lists_mappings_and_objects(agent_session: Path) -> None:
    listed = gazua.wrap([lookup_order, refund_order])
    as_tuple = gazua.wrap((lookup_order,))
    mapped = gazua.wrap(OrderedDict([("refund_order", refund_order), ("lookup", lookup_order)]))
    original = FrameworkTool("fetch_page", None, fetch_page)
    objects = gazua.wrap([original])

    assert isinstance(listed, list)
    assert [item.__name__ for item in listed] == ["lookup_order", "refund_order"]
    assert all(is_proxy(item) for item in listed)
    assert isinstance(as_tuple, tuple)
    assert isinstance(mapped, OrderedDict)
    assert list(mapped) == ["refund_order", "lookup"]
    assert is_proxy(mapped["lookup"])
    assert objects[0] is not original
    assert original.coroutine is fetch_page
    assert is_proxy(objects[0].coroutine)
    assert objects[0].description == "framework tool"


def test_mapping_key_names_the_tool(agent_session: Path, read_log: ReadLog) -> None:
    tools = gazua.wrap({"refund_order": lookup_order})

    assert tools["refund_order"](7) == {"status": "ok"}
    assert read_log(agent_session)[0]["tool"] == "refund_order"


def test_proxy_preserves_name_signature_and_docstring(agent_session: Path) -> None:
    (proxy,) = gazua.wrap([lookup_order])

    assert proxy.__name__ == "lookup_order"
    assert proxy.__doc__ == "Reads one order."
    assert proxy.__wrapped__ is lookup_order
    assert inspect.signature(proxy) == inspect.signature(lookup_order)


def test_async_tool_is_awaited_and_dry_run_is_awaitable(
    start_session: StartSession, policy: Policy, read_log: ReadLog
) -> None:
    log = start_session(tools={"fetch_page": policy(dry_run=False)})
    real = gazua.wrap([fetch_page])[0]
    assert inspect.iscoroutinefunction(real)
    assert asyncio.run(real("a")) == "page a"

    start_session(
        run_id="second",
        tools={"fetch_page": policy(has_dry_run_return=True, dry_run_return="cached")},
    )
    assert asyncio.run(real("b")) == "cached"

    records = read_log(log)
    assert [(item["dry_run"], item["result_type"]) for item in records] == [
        (False, "str"),
        (True, "str"),
    ]


def test_wrap_is_idempotent(agent_session: Path) -> None:
    first = gazua.wrap([lookup_order])[0]
    second = gazua.wrap([lookup_order])[0]

    assert first is second
    assert gazua.wrap([first])[0] is first
    assert first.__wrapped__ is lookup_order


def numbers() -> Iterator[int]:
    yield 1


async def async_numbers() -> Any:
    yield 1


class ToolClass:
    pass


@pytest.mark.parametrize(
    "unsupported",
    [
        pytest.param([numbers], id="generator"),
        pytest.param([async_numbers], id="async-generator"),
        pytest.param([ToolClass], id="class"),
        pytest.param([42], id="value"),
        pytest.param({1: lookup_order}, id="non-string-key"),
        pytest.param(lookup_order, id="bare-function"),
    ],
)
def test_unsupported_tools_are_rejected_inside_session(
    agent_session: Path, unsupported: object
) -> None:
    with pytest.raises(UnsupportedToolError):
        gazua.wrap(unsupported)


def test_unsupported_tools_pass_through_outside_a_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GAZUA_SESSION", raising=False)
    tools = [numbers, ToolClass]

    assert gazua.wrap(tools) is tools


def test_decorator_requires_no_arguments_and_matches_discovery(
    agent_session: Path, tmp_path: Path
) -> None:
    decorated = gazua.tool(refund_order)
    called = gazua.tool()(lookup_order)

    assert is_proxy(decorated)
    assert is_proxy(called)
    assert decorated("x") == {"status": "ok"}
    with pytest.raises(TypeError):
        gazua.tool(name="other")  # type: ignore[call-overload]

    project = tmp_path / "project"
    project.mkdir()
    (project / "agent.py").write_text(
        "import gazua\n"
        "@gazua.tool\ndef first(): ...\n"
        "@gazua.tool()\ndef second(): ...\n"
        "def third(): ...\n"
        "TOOLS = gazua.wrap([third])\n",
        encoding="utf-8",
    )
    found = discover_tools(project)
    assert [(item.name, item.source) for item in found.tools] == [
        ("first", "decorator"),
        ("second", "decorator"),
        ("third", "wrap"),
    ]


def test_dry_run_return_is_a_copy(start_session: StartSession, policy: Policy) -> None:
    start_session(
        tools={
            "refund_order": policy(has_dry_run_return=True, dry_run_return={"items": [1]}),
        }
    )
    (proxy,) = gazua.wrap([refund_order])

    first = proxy(1)
    first["items"].append(2)

    assert proxy(2) == {"items": [1]}


def test_registered_tools_keep_one_entry_per_name(agent_session: Path) -> None:
    gazua.wrap([lookup_order, refund_order])
    gazua.wrap([FrameworkTool("fetch_page", fetch_page, fetch_page)])

    def lookup_order_copy() -> None: ...

    gazua.wrap({"lookup_order": lookup_order_copy})
    snapshot = registry.snapshot()

    assert len(snapshot["refund_order"]) == 1
    assert len(snapshot["fetch_page"]) == 1
    assert len(snapshot["lookup_order"]) == 2


def test_dry_run_rejects_arguments_the_original_would_reject(
    agent_session: Path, read_log: ReadLog
) -> None:
    (proxy,) = gazua.wrap([refund_order])

    with pytest.raises(TypeError):
        proxy(1, 2)

    record = read_log(agent_session)[0]
    assert record["outcome"] == "raised"
    assert record["error"] == {"type": "TypeError"}


def search_documents(query: str) -> str:
    return f"results for {query}"


def search_structured(query: str) -> dict[str, str]:
    return {"query": query}


def test_injection_is_appended_to_text_results_up_to_its_limit(
    start_session: StartSession, policy: Policy, read_log: ReadLog
) -> None:
    log = start_session(
        tools={
            "search_documents": policy(dry_run=False),
            "search_structured": policy(dry_run=False),
        },
        injections=[
            {"id": "rag-1", "tool": "search_documents", "text": "ATTACK", "max_deliveries": 1},
            {"id": "rag-2", "tool": "search_structured", "text": "ATTACK", "max_deliveries": 1},
        ],
    )
    text_tool, structured_tool = gazua.wrap([search_documents, search_structured])

    assert text_tool("a") == "results for a\nATTACK"
    assert text_tool("b") == "results for b"
    assert structured_tool("c") == {"query": "c"}

    injections = [record["injection"] for record in read_log(log)]
    assert injections == [
        {"id": "rag-1", "delivered": True, "reason": None},
        None,
        {"id": "rag-2", "delivered": False, "reason": "unsupported_result_type"},
    ]
