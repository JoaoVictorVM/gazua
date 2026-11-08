"""Append-only JSONL log of tool calls, the evidence that verdicts read.

Each line is written and flushed before the call returns, so a run killed mid-attack keeps
every finished call. Return values are never written, only their type, so test data and
secrets do not end up in the evidence twice.
"""

from __future__ import annotations

import json
import math
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from gazua.integration.errors import GazuaBlockedError

RECORD_SCHEMA_VERSION = 1
MAX_VALUE_CHARS = 4096
_MAX_DEPTH = 32


def _safe_repr(value: object) -> str:
    try:
        text = repr(value)
    # repr runs the target's code, which can raise anything.
    except Exception:  # noqa: BLE001
        text = f"<{type(value).__name__}>"
    return text[:MAX_VALUE_CHARS]


def to_json_value(value: object, depth: int = 0) -> Any:
    """JSON data for any value. What JSON cannot hold becomes ``{"$repr": ...}``."""
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else {"$repr": repr(value)}
    if depth >= _MAX_DEPTH:
        return {"$repr": _safe_repr(value)}
    if isinstance(value, list | tuple):
        return [to_json_value(item, depth + 1) for item in cast("list[object]", value)]
    if isinstance(value, dict):
        items = cast("dict[object, object]", value)
        if all(isinstance(key, str) for key in items):
            return {cast("str", key): to_json_value(item, depth + 1) for key, item in items.items()}
    return {"$repr": _safe_repr(cast("object", value))}


def _dumps(value: object) -> str:
    # ASCII escapes keep lone surrogates in names and arguments writable as UTF-8.
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))


def log_arguments(arguments: Mapping[str, object]) -> tuple[dict[str, Any], bool]:
    """Arguments as JSON data, each value cut to ``MAX_VALUE_CHARS``, and whether any was cut."""
    converted: dict[str, Any] = {}
    truncated = False
    for name, value in arguments.items():
        data = to_json_value(value)
        if isinstance(data, str):
            if len(data) > MAX_VALUE_CHARS:
                data, truncated = data[:MAX_VALUE_CHARS], True
        elif len(text := _dumps(data)) > MAX_VALUE_CHARS:
            data, truncated = {"$truncated": text[:MAX_VALUE_CHARS]}, True
        converted[name] = data
    return converted, truncated


class CallLog:
    """One log file. ``seq`` grows across every thread of the process."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._next_seq: int | None = None

    def _write(self, line: str) -> None:
        # Opening per line keeps no handle alive between calls, and closing flushes the line
        # to the operating system before the call returns.
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line)

    def _first_seq(self) -> int:
        if self._next_seq is None:
            existing = self.path.read_bytes().count(b"\n") if self.path.is_file() else 0
            self._next_seq = existing + 1
        return self._next_seq

    def append(self, record: Mapping[str, Any]) -> int:
        """Writes one record and returns its ``seq``. A log that cannot be written blocks."""
        with self._lock:
            try:
                seq = self._first_seq()
                line = _dumps({"schema_version": RECORD_SCHEMA_VERSION, "seq": seq, **record})
                self._write(line + "\n")
            except (OSError, ValueError):
                raise GazuaBlockedError("call_log_unavailable") from None
            self._next_seq = seq + 1
            return seq

    def check_writable(self) -> None:
        """Fails closed before a tool runs when its call could not be recorded."""
        with self._lock:
            try:
                self._first_seq()
                self._write("")
            except (OSError, ValueError):
                raise GazuaBlockedError("call_log_unavailable") from None


_logs_lock = threading.Lock()
_logs: dict[Path, CallLog] = {}


def call_log_for(path: Path) -> CallLog:
    key = path.absolute()
    with _logs_lock:
        log = _logs.get(key)
        if log is None:
            log = _logs[key] = CallLog(key)
        return log
