"""Private capture of tool returns, next to the call log of a supervised execution.

The call log keeps only the type of a return. Proving that the attacker read a victim's record
needs the value itself, so the wrapper writes it here, in the run's private folder, which the
engine deletes once the verdict has been taken. Only plain JSON data is captured: nothing of the
target's objects is called to make a value serializable. A capture that cannot be written never
changes what the tool returns.
"""

from __future__ import annotations

import json
import math
import threading
from pathlib import Path
from typing import Any, cast

from gazua.integration.session import Session

RETURNS_FILE = "returns.private.jsonl"
MAX_OBSERVATION_BYTES = 64 * 1024
MAX_EXECUTION_BYTES = 1024 * 1024
_MAX_DEPTH = 32
_SCALARS = (str, int, bool, type(None))


class _Opaque(Exception):
    """The value is not plain JSON data."""


def native_json(value: object, depth: int = 0) -> Any:
    """``value`` when it is made only of plain JSON types, else ``_Opaque``.

    Exact type checks keep subclasses out, since their methods are the target's code.
    """
    kind = type(value)
    if kind in _SCALARS:
        return value
    if kind is float:
        if not math.isfinite(cast("float", value)):
            raise _Opaque
        return value
    if depth >= _MAX_DEPTH:
        raise _Opaque
    if kind is list or kind is tuple:
        return [native_json(item, depth + 1) for item in cast("list[object]", value)]
    if kind is dict:
        items = cast("dict[object, object]", value)
        if any(type(key) is not str for key in items):
            raise _Opaque
        return {cast("str", key): native_json(item, depth + 1) for key, item in items.items()}
    raise _Opaque


def _dumps(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))


class ReturnSidecar:
    """One sidecar file. Lines are written whole, under a lock, and flushed on close."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._written: int | None = None

    def _size(self) -> int:
        if self._written is None:
            self._written = self.path.stat().st_size if self.path.is_file() else 0
        return self._written

    def record(self, execution_id: str, seq: int, original: object, delivered: object) -> None:
        head = {"schema_version": 1, "kind": "tool_return", "execution_id": execution_id}
        try:
            line = _dumps(
                {
                    **head,
                    "call_seq": seq,
                    "original": native_json(original),
                    "delivered": native_json(delivered),
                }
            )
            reason = "too_large" if len(line) > MAX_OBSERVATION_BYTES else None
        except (_Opaque, ValueError, RecursionError):
            line, reason = "", "not_serializable"
        with self._lock:
            try:
                if reason is None and self._size() + len(line) + 1 > MAX_EXECUTION_BYTES:
                    reason = "execution_limit"
                if reason is not None:
                    line = _dumps({**head, "call_seq": seq, "unavailable_reason": reason})
                with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                    handle.write(line + "\n")
                self._written = self._size() + len(line) + 1
            except OSError:
                # The reader sees a returned call without its line and treats it as missing.
                return


_sidecars_lock = threading.Lock()
_sidecars: dict[Path, ReturnSidecar] = {}


def sidecar_for(session: Session) -> ReturnSidecar | None:
    """The sidecar of a version 2 session. Version 1 sessions keep their earlier behavior."""
    if session.execution is None:
        return None
    key = (session.call_log.parent / RETURNS_FILE).absolute()
    with _sidecars_lock:
        sidecar = _sidecars.get(key)
        if sidecar is None:
            sidecar = _sidecars[key] = ReturnSidecar(key)
        return sidecar


def record_return(session: Session, seq: int, original: object, delivered: object) -> None:
    """Writes the return of call ``seq``. Never raises into the tool's caller."""
    sidecar = sidecar_for(session)
    if sidecar is None or session.execution is None:
        return
    sidecar.record(session.execution.execution_id, seq, original, delivered)


def clear_sidecars() -> None:
    with _sidecars_lock:
        _sidecars.clear()
