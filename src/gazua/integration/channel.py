"""Append-only event channel from the tested process to the Gazua supervisor.

The supervisor reads this file while the execution runs, so it learns about the tool call
ceiling, reported usage and rate limits without trusting anything the target prints. Each
event is one JSON line; a line is complete before the call that produced it goes on.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from gazua.integration.session import ExecutionChannel

EVENT_SCHEMA_VERSION = 1
MAX_EVENT_BYTES = 64 * 1024
MAX_EVENTS = 4096


class ChannelError(Exception):
    """An event could not be written. Callers fail closed."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class EventChannel:
    """The events of one execution. ``seq`` grows across every thread of the process."""

    def __init__(self, path: Path, execution_id: str) -> None:
        self.path = path
        self.execution_id = execution_id
        self._lock = threading.Lock()
        self._seq = 0

    def emit(self, kind: str, payload: Mapping[str, Any], *, sync: bool = False) -> int:
        """Writes one event and returns its ``seq``. ``sync`` also asks the disk to keep it."""
        with self._lock:
            seq = self._seq + 1
            if seq > MAX_EVENTS:
                raise ChannelError("channel_saturated")
            event = {
                "schema_version": EVENT_SCHEMA_VERSION,
                "execution_id": self.execution_id,
                "seq": seq,
                "kind": kind,
                "payload": dict(payload),
            }
            try:
                line = json.dumps(event, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
            except (TypeError, ValueError):
                raise ChannelError("event_invalid") from None
            if len(line) + 1 > MAX_EVENT_BYTES:
                raise ChannelError("event_too_large")
            try:
                with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                    handle.write(line + "\n")
                    if sync:
                        handle.flush()
                        os.fsync(handle.fileno())
            except (OSError, ValueError):
                raise ChannelError("channel_unavailable") from None
            self._seq = seq
            return seq


_channels_lock = threading.Lock()
_channels: dict[Path, EventChannel] = {}


def channel_for(execution: ExecutionChannel) -> EventChannel:
    key = execution.events_path.absolute()
    with _channels_lock:
        channel = _channels.get(key)
        if channel is None:
            channel = _channels[key] = EventChannel(key, execution.execution_id)
        return channel


def clear_channels() -> None:
    with _channels_lock:
        _channels.clear()
