"""Optional signals from the tested agent: incremental usage cost and rate limits.

Gazua never sees the agent's model calls, so cost and 429 responses are known only when the
test entrypoint reports them here. Both are no-ops outside a supervised execution, and nothing
here opens a network connection or reads credentials.
"""

from __future__ import annotations

import math
import uuid

from gazua.integration.channel import ChannelError, channel_for
from gazua.integration.session import InvalidSession, session_state


def _finite_non_negative(value: object, name: str) -> float | int:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise TypeError(f"{name} must be a number.")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"{name} must be finite.")
    if value < 0:
        raise ValueError(f"{name} must not be negative.")
    return value


class GazuaRateLimited(Exception):
    """Raise from the test entrypoint when the model provider answered 429.

    ``retry_after`` is the wait in seconds the provider asked for, when it said one. Gazua
    recognizes a rate limit only through this exception, never by reading error messages.
    """

    def __init__(self, retry_after: float | None = None) -> None:
        self.retry_after = (
            None if retry_after is None else float(_finite_non_negative(retry_after, "retry_after"))
        )
        super().__init__("The target reported a rate limit (429).")


def report_usage(*, cost_usd: float) -> bool:
    """Reports the cost in USD of the model calls made since the previous report.

    Each call adds an increment; never pass a running total. Returns True when the cost reached
    the supervisor and False outside a supervised execution, where the call does nothing.
    """
    value = _finite_non_negative(cost_usd, "cost_usd")
    state = session_state()
    if state is None or isinstance(state, InvalidSession) or state.execution is None:
        return False
    text = repr(float(value)) if isinstance(value, float) else str(value)
    try:
        channel_for(state.execution).emit(
            "usage", {"usage_id": uuid.uuid4().hex, "cost_usd": text}, sync=True
        )
    except ChannelError:
        return False
    return True
