"""MCP integration over stdio, installed with the optional ``gazua[mcp]`` extra.

Importing this package never imports the MCP SDK: only the modules that start a server or a
broker do, and only on MCP paths. Python targets and ``gazua --help`` keep working without the
extra.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from typing import Final

EXTRA_MISSING_CODE: Final = "mcp_extra_missing"
EXTRA_MISSING_MESSAGE: Final = "This target needs MCP support. Install gazua[mcp]."
BROKER_ENV: Final = "GAZUA_MCP_BROKER"
PROXY_COMMAND: Final = "mcp-proxy"


def gazua_version() -> str:
    """The installed version, announced to MCP peers; never used to decide anything."""
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("gazua")
    except PackageNotFoundError:
        return "0"


def extra_available() -> bool:
    """Whether the MCP SDK and the schema validator of the extra are importable."""
    return all(importlib.util.find_spec(name) is not None for name in ("mcp", "jsonschema"))


def proxy_server_parameters() -> dict[str, object]:
    """How a test agent's MCP client starts ``gazua mcp-proxy`` in place of the real server.

    Use it inside the test entrypoint, during a Gazua run: the environment carries only the
    location of this attempt's private broker context. Outside a run it raises ``RuntimeError``.
    """
    location = os.environ.get(BROKER_ENV)
    if not location:
        raise RuntimeError("gazua mcp-proxy only works inside a Gazua agent run.")
    return {
        "command": sys.executable,
        "args": ["-m", "gazua", PROXY_COMMAND],
        "env": {BROKER_ENV: location},
    }


__all__ = [
    "BROKER_ENV",
    "EXTRA_MISSING_CODE",
    "EXTRA_MISSING_MESSAGE",
    "PROXY_COMMAND",
    "extra_available",
    "gazua_version",
    "proxy_server_parameters",
]
