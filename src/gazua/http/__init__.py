"""HTTP target adapter for agent mode.

Importing this package opens no socket and imports no optional dependency. The client, the
policy and the executor live in their own modules and are imported only on HTTP paths.
"""

from __future__ import annotations

from typing import Final

EXECUTOR: Final = "gazua.http.executor:execute"
RECEIPT_FILE: Final = "authorization-v1.json"
RUN_HEADER: Final = "X-Gazua-Run"
OTLP_ENDPOINT_HEADER: Final = "X-Gazua-OTLP-Endpoint"
TRACE_TOKEN_HEADER: Final = "X-Gazua-Trace-Token"  # noqa: S105 - a header name, not a secret


def user_agent() -> str:
    """``gazua/<version>``, sent with every request so the target can tell Gazua apart."""
    from importlib.metadata import PackageNotFoundError, version

    try:
        installed = version("gazua")
    except PackageNotFoundError:
        installed = "0"
    return f"gazua/{installed}"


__all__ = [
    "EXECUTOR",
    "OTLP_ENDPOINT_HEADER",
    "RECEIPT_FILE",
    "RUN_HEADER",
    "TRACE_TOKEN_HEADER",
    "user_agent",
]
