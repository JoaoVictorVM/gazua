"""Target side of the tool contract. Imports only the standard library."""

from gazua.integration.errors import GazuaBlockedError, UnsupportedToolError
from gazua.integration.receiver import GazuaReceiverError, send_to_receiver
from gazua.integration.telemetry import (
    GazuaAuthenticationError,
    GazuaRateLimited,
    report_usage,
)
from gazua.integration.wrapping import tool, wrap

__all__ = [
    "GazuaAuthenticationError",
    "GazuaBlockedError",
    "GazuaRateLimited",
    "GazuaReceiverError",
    "UnsupportedToolError",
    "report_usage",
    "send_to_receiver",
    "tool",
    "wrap",
]
