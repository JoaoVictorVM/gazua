"""MCP results as the native call evidence, and the private channel of description deliveries.

A result becomes the value the call log and the return channel already know: validated
``structuredContent`` first, then one text block as a string, several as a list of strings.
Mixed or binary content stays typed JSON; nothing is decoded, fetched or parsed from text.

The delivery channel is a JSONL file in the attempt's private folder, written by the broker
only. It never holds the token, the original description or the attack text: only which
injection reached the agent's client, on which surface and in which order relative to calls.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from pydantic import TypeAdapter, ValidationError

from gazua.mcp.models import (
    MAX_DELIVERY_BYTES,
    MAX_DELIVERY_EVENTS,
    CallEvent,
    DeliveryEvent,
    DeliverySurface,
)


class McpToolError(Exception):
    """The server answered ``isError: true``. The call ran: it is an application error."""

    def __init__(self, result: Mapping[str, Any]) -> None:
        self.result = dict(result)
        super().__init__("The MCP tool returned an error.")


def _texts(content: list[Any]) -> list[str] | None:
    texts: list[str] = []
    for block in content:
        if not isinstance(block, dict):
            return None
        item = cast("dict[str, Any]", block)
        if item.get("type") != "text" or not isinstance(item.get("text"), str):
            return None
        texts.append(cast("str", item["text"]))
    return texts


def normalize_result(result: Mapping[str, Any]) -> Any:
    """The value Gazua records for one successful MCP result."""
    structured = result.get("structuredContent")
    if isinstance(structured, dict):
        return cast("dict[str, Any]", structured)
    content = result.get("content")
    if not isinstance(content, list):
        return None
    blocks = cast("list[Any]", content)
    texts = _texts(blocks)
    if texts is None:
        return {"content": blocks}
    if len(texts) == 1:
        return texts[0]
    return texts


def _text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def to_call_result(value: Any) -> dict[str, Any]:
    """The MCP result the agent's client receives for a value Gazua returns.

    It is used for dry-run values and for real results after an injection. A string is one
    text block; an object is ``structuredContent`` with its JSON text; anything else is text.
    """
    if isinstance(value, str):
        return {"content": [{"type": "text", "text": value}], "isError": False}
    if isinstance(value, dict):
        data = cast("dict[str, Any]", value)
        if set(data) == {"content"} and isinstance(data["content"], list):
            return {"content": data["content"], "isError": False}
        return {
            "content": [{"type": "text", "text": _text(data)}],
            "structuredContent": data,
            "isError": False,
        }
    if isinstance(value, list) and all(isinstance(item, str) for item in cast("list[Any]", value)):
        texts = cast("list[str]", value)
        return {"content": [{"type": "text", "text": item} for item in texts], "isError": False}
    return {"content": [{"type": "text", "text": _text(value)}], "isError": False}


class DeliveryLog:
    """Writer of one attempt's delivery channel. Orders grow across deliveries and calls."""

    def __init__(self, path: Path, execution_id: str) -> None:
        self.path = path
        self.execution_id = execution_id
        self._lock = threading.Lock()
        self._order = 0
        self._events = 0
        self._bytes = 0
        self.full = False
        self.delivered: set[str] = set()

    def _append(self, document: dict[str, Any]) -> bool:
        line = json.dumps(document, ensure_ascii=True, separators=(",", ":")) + "\n"
        if self._events + 1 > MAX_DELIVERY_EVENTS or self._bytes + len(line) > MAX_DELIVERY_BYTES:
            self.full = True
            return False
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
        self._events += 1
        self._bytes += len(line)
        return True

    def delivery(
        self,
        *,
        injection_id: str,
        turn: int,
        tool: str,
        surface: DeliverySurface,
        delivered: bool,
        reason: str | None,
        call_seq: int | None = None,
    ) -> bool:
        """Records one delivery or its absence; a second delivery of the same id is ignored."""
        with self._lock:
            if injection_id in self.delivered:
                return False
            self._order += 1
            written = self._append(
                {
                    "schema_version": 1,
                    "kind": "delivery",
                    "execution_id": self.execution_id,
                    "order": self._order,
                    "injection_id": injection_id,
                    "turn": turn,
                    "tool": tool,
                    "surface": surface,
                    "delivered": delivered,
                    "reason": reason,
                    "call_seq": call_seq,
                }
            )
            if written and delivered:
                self.delivered.add(injection_id)
            return written

    def call(self, call_seq: int) -> bool:
        with self._lock:
            self._order += 1
            return self._append(
                {
                    "schema_version": 1,
                    "kind": "call",
                    "execution_id": self.execution_id,
                    "order": self._order,
                    "call_seq": call_seq,
                }
            )


_EVENT = TypeAdapter(DeliveryEvent | CallEvent)


@dataclass(frozen=True, slots=True)
class DeliveryChannel:
    """What the verdict engine reads. ``complete`` False means nothing can be attributed."""

    deliveries: tuple[DeliveryEvent, ...]
    calls: tuple[CallEvent, ...]
    complete: bool

    def delivered_order(self, injection_id: str, tool: str) -> int | None:
        for event in self.deliveries:
            if event.injection_id == injection_id and event.tool == tool and event.delivered:
                return event.order
        return None

    def call_order(self, call_seq: int) -> int | None:
        return next((event.order for event in self.calls if event.call_seq == call_seq), None)


def read_delivery_channel(path: Path, execution_id: str) -> DeliveryChannel | None:
    """The channel of one attempt, or None when the attempt never wrote one.

    A truncated line, a foreign execution id, a repeated order or call, a second positive
    delivery of an injection, or a channel past its limits makes it incomplete.
    """
    if not path.is_file():
        return None
    try:
        content = path.read_bytes()
    except OSError:
        return DeliveryChannel((), (), complete=False)
    if len(content) > MAX_DELIVERY_BYTES or (content and not content.endswith(b"\n")):
        return DeliveryChannel((), (), complete=False)
    deliveries: list[DeliveryEvent] = []
    calls: list[CallEvent] = []
    last = 0
    positive: set[str] = set()
    sequences: set[int] = set()
    lines = content.split(b"\n")[:-1]
    if len(lines) > MAX_DELIVERY_EVENTS:
        return DeliveryChannel((), (), complete=False)
    for line in lines:
        try:
            event = _EVENT.validate_json(line)
        except ValidationError:
            return DeliveryChannel(tuple(deliveries), tuple(calls), complete=False)
        if event.execution_id != execution_id or event.order <= last:
            return DeliveryChannel(tuple(deliveries), tuple(calls), complete=False)
        last = event.order
        if isinstance(event, CallEvent):
            if event.call_seq in sequences:
                return DeliveryChannel(tuple(deliveries), tuple(calls), complete=False)
            sequences.add(event.call_seq)
            calls.append(event)
            continue
        if event.delivered:
            if event.injection_id in positive or event.reason is not None:
                return DeliveryChannel(tuple(deliveries), tuple(calls), complete=False)
            positive.add(event.injection_id)
        elif event.reason is None:
            return DeliveryChannel(tuple(deliveries), tuple(calls), complete=False)
        deliveries.append(event)
    return DeliveryChannel(tuple(deliveries), tuple(calls), complete=True)
