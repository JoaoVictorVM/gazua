"""Agent mode executor for an HTTP target, run by the engine inside each supervised worker.

The mold is bound and checked exactly as for a Python entrypoint; only the delivery changes:
each turn becomes one ``POST`` to the authorized endpoint, in this worker and attempt. When the
configuration reads traces, a loopback OTLP receiver lives for the attempt, its endpoint and
token reach the target only in two request headers, and the private sidecar keeps the minimal
tool span evidence. Nothing here imports the target or reads the environment.
"""

from __future__ import annotations

import time
from collections.abc import Generator, Mapping
from contextlib import contextmanager
from typing import Any, Final

from gazua.config.models import GazuaConfig
from gazua.diagnostics import ConfigError
from gazua.http.client import HttpAttemptFailed, HttpClient, HttpRateLimited
from gazua.http.models import REAL_SIDE_EFFECTS
from gazua.runtime.worker import ExecutionContext

# The worker must write its result and sidecar before the supervisor's deadline kills it.
DEADLINE_MARGIN: Final = 0.5
QUIET_POLL: Final = 0.02
MAX_TOOL_CHARACTERS: Final = 256


def attempt_id(context: ExecutionContext) -> str:
    """The id sent as ``X-Gazua-Run`` and ``run_id``: one per attempt, never reused."""
    return f"{context.run_id}:{context.execution_id}"


def _deadline(context: ExecutionContext) -> float:
    config: GazuaConfig = context.config
    if context.deadline is not None:
        return context.deadline - DEADLINE_MARGIN
    return time.monotonic() + float(config.limits.timeout) - DEADLINE_MARGIN


def _client(context: ExecutionContext, deadline: float, extra: Mapping[str, str]) -> HttpClient:
    from gazua.http.policy import check_destination

    config: GazuaConfig = context.config
    http = config.http
    if http is None:
        raise HttpAttemptFailed("http_target_missing")
    try:
        endpoint = check_destination(config)
    except ConfigError as error:
        raise HttpAttemptFailed(error.diagnostics[0].code) from None
    if http.real_side_effects != REAL_SIDE_EFFECTS:
        raise HttpAttemptFailed("http_real_side_effects_missing")
    return HttpClient(
        endpoint, http.headers, attempt_id(context), deadline=deadline, extra_headers=extra
    )


def _sender(client: HttpClient) -> Any:
    from gazua.runtime.hooks import RateLimited

    def send(message: str) -> str:
        try:
            return client.send(message)
        except HttpRateLimited as limited:
            raise RateLimited("http", limited.retry_after) from None

    return send


def wait_for_quiet(collector: Any, quiet_seconds: float, deadline: float) -> None:
    """Waits until no batch arrived for ``quiet_seconds``, never past ``deadline``."""
    while True:
        now = time.monotonic()
        if now >= deadline or now - collector.last_activity >= quiet_seconds:
            return
        time.sleep(QUIET_POLL)


def redacted(evidence: Any, config: GazuaConfig) -> Any:
    """The evidence with undeclared tool names passed through the redactor."""
    from gazua.runtime.evidence import Redactor

    redactor = Redactor(config.canaries)
    spans = [
        span
        if span.tool in config.tools
        else span.model_copy(
            update={"tool": (redactor.text(span.tool) or "-")[:MAX_TOOL_CHARACTERS]}
        )
        for span in evidence.tool_spans
    ]
    return evidence.model_copy(update={"tool_spans": spans})


@contextmanager
def http_attempt(context: ExecutionContext) -> Generator[Any]:
    """A sender for this attempt's turns, with the trace receiver around it when declared."""
    config: GazuaConfig = context.config
    deadline = _deadline(context)
    if config.traces is None:
        yield _sender(_client(context, deadline, {}))
        return
    from gazua.otel import TRACE_FILE, extra_available
    from gazua.otel.evidence import TraceCollector, write_trace_evidence
    from gazua.otel.receiver import OtlpReceiver, ReceiverUnavailable

    if not extra_available():
        raise HttpAttemptFailed("otel_extra_missing")
    collector = TraceCollector(context.execution_id, attempt_id(context), time.time_ns())
    receiver = OtlpReceiver(collector)
    try:
        receiver.start()
    except ReceiverUnavailable:
        # The response and canaries still count; tool visibility does not.
        collector.fail("otel_receiver_unavailable")
        try:
            yield _sender(_client(context, deadline, {}))
        finally:
            collector.close()
            write_trace_evidence(
                context.directory / TRACE_FILE, redacted(collector.evidence(), config)
            )
        return
    try:
        yield _sender(_client(context, deadline, receiver.headers()))
        wait_for_quiet(collector, config.traces.wait_seconds, deadline)
    finally:
        receiver.stop()
        write_trace_evidence(context.directory / TRACE_FILE, redacted(collector.evidence(), config))


def execute(request: Mapping[str, Any], context: ExecutionContext) -> dict[str, Any]:
    """Runs one agent attack or legitimate task against the HTTP endpoint."""
    from gazua.modes.agent_executor import dispatch

    with http_attempt(context) as send:
        return dispatch(request, context, send)


__all__ = ["attempt_id", "execute", "http_attempt", "wait_for_quiet"]
