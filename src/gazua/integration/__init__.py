"""Target side of the tool contract. Imports only the standard library."""

from gazua.integration.errors import GazuaBlockedError, UnsupportedToolError

__all__ = ["GazuaBlockedError", "UnsupportedToolError"]
