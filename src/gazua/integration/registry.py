"""Tools wrapped in this process, so Gazua can find and call them by name."""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class RegisteredTool:
    """One tool. A framework object can bring both a sync and an async function."""

    name: str
    originals: list[Callable[..., Any]] = field(default_factory=list[Callable[..., Any]])
    proxy: Callable[..., Any] | None = None
    async_proxy: Callable[..., Any] | None = None

    def owns(self, original: Callable[..., Any]) -> bool:
        return any(known is original for known in self.originals)


class ToolRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tools: dict[str, list[RegisteredTool]] = {}
        self._proxies: dict[tuple[str, int], tuple[Callable[..., Any], Callable[..., Any]]] = {}

    def cached_proxy(self, name: str, original: Callable[..., Any]) -> Callable[..., Any] | None:
        with self._lock:
            cached = self._proxies.get((name, id(original)))
        if cached is not None and cached[0] is original:
            return cached[1]
        return None

    def register(
        self,
        name: str,
        original: Callable[..., Any],
        proxy: Callable[..., Any],
        *,
        is_async: bool,
        companion: Callable[..., Any] | None = None,
    ) -> None:
        """Adds a proxy. ``companion`` is the other function of the same framework object."""
        with self._lock:
            self._proxies[(name, id(original))] = (original, proxy)
            entries = self._tools.setdefault(name, [])
            entry = next(
                (
                    item
                    for item in entries
                    if item.owns(original) or (companion is not None and item.owns(companion))
                ),
                None,
            )
            if entry is None:
                entry = RegisteredTool(name)
                entries.append(entry)
            if not entry.owns(original):
                entry.originals.append(original)
            if is_async:
                entry.async_proxy = proxy
            else:
                entry.proxy = proxy

    def snapshot(self) -> dict[str, tuple[RegisteredTool, ...]]:
        """Every registered name. More than one entry under a name is a conflict."""
        with self._lock:
            return {name: tuple(entries) for name, entries in self._tools.items()}

    def clear(self) -> None:
        with self._lock:
            self._tools.clear()
            self._proxies.clear()


registry = ToolRegistry()
