"""Errors raised inside the tested process. Their messages never carry argument values."""

from __future__ import annotations


class GazuaBlockedError(Exception):
    """A tool call was stopped before the original function ran.

    Raised when running the tool for real would be unsafe or when the run's session cannot be
    trusted. ``reason`` is a short code that also goes to the call log.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"Gazua blocked this tool call ({reason}).")


class UnsupportedToolError(TypeError):
    """``gazua.wrap`` received something that cannot become a tool inside a run."""
