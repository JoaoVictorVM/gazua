"""Target side of the tool contract. Imports only the standard library."""

from gazua.integration.errors import GazuaBlockedError, UnsupportedToolError
from gazua.integration.wrapping import tool, wrap

__all__ = ["GazuaBlockedError", "UnsupportedToolError", "tool", "wrap"]
