"""Run slots, cost reservations in decimal USD, reported usage and backoff after a 429.

``max_runs`` counts attack attempts that started, retries included. A slot is reserved before
launch and never given back, whatever happened to the attempt. Missing usage never counts as
zero cost.
"""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

from gazua.runtime.run_models import CostSource

MAX_BACKOFF_SECONDS = 60.0
DEFAULT_BACKOFF_SECONDS = (1.0, 2.0)


def to_decimal(value: float | int | str) -> Decimal:
    """Exact decimal of a validated number, through its shortest text form."""
    try:
        result = Decimal(repr(value) if isinstance(value, float) else str(value))
    except InvalidOperation:
        raise ValueError("Not a decimal number.") from None
    if not result.is_finite() or result < 0:
        raise ValueError("Costs must be finite and non-negative.")
    return result


def decimal_text(value: Decimal) -> str:
    """Plain notation without exponent or trailing zeros, as execution records store it."""
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


@dataclass(frozen=True, slots=True)
class Admission:
    """A granted slot, with the estimate reserved for it when one applies."""

    number: int
    estimate: Decimal | None


class RunBudget:
    """Slots and cost of one run. Every method is safe to call from several threads."""

    def __init__(
        self,
        *,
        max_runs: int,
        max_cost: Decimal | None,
        cost_per_run: Decimal | None,
        source: CostSource,
    ) -> None:
        self.max_runs = max_runs
        self.max_cost = max_cost
        self.cost_per_run = cost_per_run
        self.source = source
        self._lock = threading.Lock()
        self._started = 0
        self._reserved = Decimal(0)
        self._reported = Decimal(0)
        self._usage_ids: set[str] = set()

    @property
    def started(self) -> int:
        with self._lock:
            return self._started

    @property
    def reserved(self) -> Decimal:
        with self._lock:
            return self._reserved

    @property
    def reported(self) -> Decimal:
        with self._lock:
            return self._reported

    def reserve(self) -> Admission | str:
        """A slot for one attempt, or the code of the limit that refuses it."""
        with self._lock:
            if self._started >= self.max_runs:
                return "max_runs"
            if self.max_cost is not None:
                if (
                    self.cost_per_run is not None
                    and self._reserved + self.cost_per_run > self.max_cost
                ):
                    return "max_cost"
                if self.source == "reported" and self._reported >= self.max_cost:
                    return "max_cost"
            self._started += 1
            if self.cost_per_run is not None:
                self._reserved += self.cost_per_run
            return Admission(self._started, self.cost_per_run)

    def record_usage(self, usage_id: str, cost: Decimal) -> bool:
        """Adds one reported increment. A repeated ``usage_id`` is ignored."""
        with self._lock:
            if usage_id in self._usage_ids:
                return False
            self._usage_ids.add(usage_id)
            self._reported += cost
            return True

    @property
    def reported_exhausted(self) -> bool:
        """Observed usage reached ``max_cost``; only meaningful when usage governs the budget."""
        with self._lock:
            return (
                self.source == "reported"
                and self.max_cost is not None
                and self._reported >= self.max_cost
            )


class Capacity:
    """How many attempts may run at once. Each 429 halves it, never below one."""

    def __init__(self, initial: int) -> None:
        self._lock = threading.Lock()
        self._value = max(1, initial)

    @property
    def value(self) -> int:
        with self._lock:
            return self._value

    def halve(self) -> int:
        with self._lock:
            self._value = max(1, self._value // 2)
            return self._value


def backoff_delay(retry_index: int, retry_after: float | None) -> float:
    """Seconds to wait before retry number ``retry_index`` (from zero) after a 429."""
    if retry_after is not None and math.isfinite(retry_after) and retry_after >= 0:
        return min(retry_after, MAX_BACKOFF_SECONDS)
    return DEFAULT_BACKOFF_SECONDS[min(retry_index, len(DEFAULT_BACKOFF_SECONDS) - 1)]


def wait_cancelable(delay: float, cancel: threading.Event) -> bool:
    """Waits on a monotonic clock. False when ``cancel`` was set first."""
    return not cancel.wait(delay)


def retry_refusal(
    *, attempt: int, max_retries: int, real_tool_called: bool, has_reset: bool
) -> str | None:
    """Why a rate limited attempt may not be retried, or ``None`` when it may.

    A retry repeats the attack, so it is allowed only when the attempt changed nothing for real
    or when ``target.reset`` restores the state before the new attempt.
    """
    if attempt > max_retries:
        return "retries_exhausted"
    if real_tool_called and not has_reset:
        return "retry_unsafe"
    return None
