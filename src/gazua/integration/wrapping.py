"""``gazua.wrap`` and ``gazua.tool``: the two ways a target hands its tools to Gazua."""

from __future__ import annotations

import copy
import inspect
from collections.abc import Callable, Mapping, MutableMapping
from typing import Any, TypeVar, cast, overload

from gazua.integration.errors import UnsupportedToolError
from gazua.integration.proxy import is_proxy, make_proxy
from gazua.integration.registry import registry
from gazua.integration.session import session_state

_Tools = TypeVar("_Tools")
_Function = TypeVar("_Function", bound=Callable[..., Any])


def _proxy_for(
    name: str, original: Callable[..., Any], companion: Callable[..., Any] | None = None
) -> Callable[..., Any]:
    if is_proxy(original):
        return original
    cached = registry.cached_proxy(name, original)
    if cached is not None:
        return cached
    proxy = make_proxy(name, original)
    registry.register(
        name,
        original,
        proxy,
        is_async=inspect.iscoroutinefunction(original),
        companion=companion,
    )
    return proxy


def _wrap_function(item: object, name: str | None) -> Callable[..., Any]:
    if inspect.isclass(item) or not callable(item):
        raise UnsupportedToolError("A tool must be a function, not a class or a plain value.")
    if inspect.isgeneratorfunction(item) or inspect.isasyncgenfunction(item):
        raise UnsupportedToolError("Generator functions cannot be wrapped as tools.")
    function = cast("Callable[..., Any]", item)
    tool_name = name if name is not None else getattr(function, "__name__", None)
    if not isinstance(tool_name, str) or not tool_name:
        raise UnsupportedToolError("A tool needs a name; pass it in a dict.")
    return _proxy_for(tool_name, function)


def _is_tool_object(item: object) -> bool:
    return isinstance(getattr(item, "name", None), str) and (
        callable(getattr(item, "func", None)) or callable(getattr(item, "coroutine", None))
    )


def _wrap_object(item: object) -> object:
    """A shallow copy of a framework tool with its functions replaced by proxies."""
    name = cast("str", getattr(item, "name"))  # noqa: B009
    func = getattr(item, "func", None)
    coroutine = getattr(item, "coroutine", None)
    updates: dict[str, Any] = {}
    if callable(func):
        updates["func"] = _proxy_for(name, func, coroutine if callable(coroutine) else None)
    if callable(coroutine):
        updates["coroutine"] = _proxy_for(name, coroutine, func if callable(func) else None)
    try:
        model_copy = getattr(item, "model_copy", None)
        if callable(model_copy):
            return model_copy(update=updates)
        clone = copy.copy(item)
        for attribute, value in updates.items():
            setattr(clone, attribute, value)
    # Copying runs the framework's code; any failure means the object cannot be wrapped.
    except Exception as error:  # noqa: BLE001
        raise UnsupportedToolError(
            f"This {type(item).__name__} tool could not be copied ({type(error).__name__})."
        ) from None
    return clone


def _wrap_item(item: object, name: str | None = None) -> object:
    if is_proxy(item):
        return item
    if name is None and _is_tool_object(item):
        return _wrap_object(item)
    return _wrap_function(item, name)


def wrap(tools: _Tools) -> _Tools:
    """Returns the same tools as proxies for a Gazua run, or unchanged outside of one.

    Accepts a list or tuple of functions, a dict from tool name to function, or a list of
    framework tool objects with ``name`` and ``func`` (and optionally ``coroutine``). The
    container keeps its type and order, and tool objects are copied, never changed in place.
    """
    if session_state() is None:
        return tools
    if isinstance(tools, Mapping):
        if not all(isinstance(key, str) for key in cast("Mapping[object, object]", tools)):
            raise UnsupportedToolError("Tool names in a dict must be strings.")
        items = cast("Mapping[str, object]", tools)
        if isinstance(items, MutableMapping):
            wrapped = copy.copy(items)
            for key, value in list(wrapped.items()):
                wrapped[key] = _wrap_item(value, key)
            return cast("_Tools", wrapped)
        return cast("_Tools", {key: _wrap_item(value, key) for key, value in items.items()})
    if isinstance(tools, list):
        return cast("_Tools", [_wrap_item(item) for item in cast("list[object]", tools)])
    if isinstance(tools, tuple):
        return cast("_Tools", tuple(_wrap_item(item) for item in cast("tuple[object, ...]", tools)))
    raise UnsupportedToolError("gazua.wrap expects a list, a tuple or a dict of tools.")


@overload
def tool(function: _Function, /) -> _Function: ...
@overload
def tool() -> Callable[[_Function], _Function]: ...
def tool(function: _Function | None = None, /) -> _Function | Callable[[_Function], _Function]:
    """Marks a function as a tool. Outside a Gazua run it returns the function itself."""
    if function is None:
        return tool
    if session_state() is None:
        return function
    return cast("_Function", _wrap_function(function, None))
