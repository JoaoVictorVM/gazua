"""Errors raised inside the tested process. Their messages never carry argument values."""

from __future__ import annotations


class GazuaBlockedError(Exception):
    """A tool call was stopped before the original function ran.

    Raised when running the tool for real would be unsafe or when the run's session cannot be
    trusted. ``reason`` is a short code that also goes to the call log.
    """

    def __init__(self, reason: str, detail: str | None = None) -> None:
        self.reason = reason
        self.detail = detail
        code = f"{reason}: {detail}" if detail else reason
        super().__init__(f"Gazua blocked this tool call ({code}).")


class UnsupportedToolError(TypeError):
    """``gazua.wrap`` received something that cannot become a tool inside a run."""
