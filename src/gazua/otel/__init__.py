"""Tool spans over OTLP/HTTP, installed with the optional ``gazua[otel]`` extra.

Importing this package never imports OpenTelemetry or protobuf: only the decoder does, and
only when a configuration declares ``traces``. The base installation keeps working without it.
"""

from __future__ import annotations

import importlib.util
from typing import Final

EXTRA_MISSING_CODE: Final = "otel_extra_missing"
EXTRA_MISSING_MESSAGE: Final = "This configuration reads traces. Install gazua[otel]."
TRACE_FILE: Final = "traces.json"


def extra_available() -> bool:
    """Whether the OTLP protobuf contracts of the extra are importable."""
    try:
        return all(
            importlib.util.find_spec(name) is not None
            for name in ("google.protobuf", "opentelemetry.proto")
        )
    except (ImportError, ValueError):
        return False


__all__ = ["EXTRA_MISSING_CODE", "EXTRA_MISSING_MESSAGE", "TRACE_FILE", "extra_available"]
