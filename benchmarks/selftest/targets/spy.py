"""Records every real effect of a benchmark target, in the process where it happens.

Each process appends JSON lines to ``effects/<pid>.jsonl`` under its working directory, which
is the cell's workspace. Credential reads and network attempts are recorded once this module
is imported, so the benchmark proves that the simulated profile touched neither.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Final

EFFECTS: Final = Path("effects")
CREDENTIAL_SUFFIXES: Final = ("_API_KEY", "_TOKEN", "_SECRET", "_PASSWORD")
NETWORK_EVENTS: Final = ("socket.connect", "socket.getaddrinfo", "http.", "urllib.")
LOOPBACK: Final = frozenset({"127.0.0.1", "::1", "localhost"})

_installed = False


def effect(kind: str, **data: Any) -> None:
    EFFECTS.mkdir(exist_ok=True)
    with (EFFECTS / f"{os.getpid()}.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"kind": kind, **data}, sort_keys=True) + "\n")


def _host(event: str, args: tuple[object, ...]) -> str | None:
    if event == "socket.connect" and len(args) > 1 and isinstance(args[1], tuple):
        address: tuple[object, ...] = args[1]  # type: ignore[assignment]
        return str(address[0]) if address else None
    if event == "socket.getaddrinfo" and args:
        return str(args[0])
    return None


def _audit(event: str, args: tuple[object, ...]) -> None:
    if not event.startswith(NETWORK_EVENTS):
        return
    # asyncio's self-pipe is a loopback socket pair on Windows; that is IPC, not network.
    if _host(event, args) in LOOPBACK:
        effect("loopback", event=event)
    else:
        effect("network", event=event)


class _Watched(type(os.environ)):  # type: ignore[misc]
    def __getitem__(self, key: str) -> str:
        if key.upper().endswith(CREDENTIAL_SUFFIXES):
            effect("credential_read", name=key)
        return super().__getitem__(key)  # type: ignore[no-any-return]


def install() -> None:
    """Starts recording credential reads and network attempts; calling it again does nothing."""
    global _installed
    if _installed:
        return
    _installed = True
    os.environ.__class__ = _Watched
    sys.addaudithook(_audit)


def read_effects(root: Path) -> list[dict[str, Any]]:
    """Every recorded effect of the workspace, in file and line order."""
    folder = root / EFFECTS
    if not folder.is_dir():
        return []
    found: list[dict[str, Any]] = []
    for path in sorted(folder.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            found.append(json.loads(line))
    return found


__all__ = ["effect", "install", "read_effects"]
