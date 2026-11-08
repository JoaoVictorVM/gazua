"""Structured observations of effects, as executors and the wrapper report them.

Three sources exist. The wrapper writes the private return of each tool call to a sidecar next
to the call log. A trusted executor puts sink and memory observations in an envelope inside its
``output``. Everything else in an output is the agent's response, never an observation. None of
these documents can carry a verdict: they say what was observed, and the verdict engine decides.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError, model_validator

from gazua.integration.observations import (
    MAX_EXECUTION_BYTES,
    MAX_OBSERVATION_BYTES,
    RETURNS_FILE,
)
from gazua.runtime.run_models import GazuaId, NonEmptyText
from gazua.runtime.session_models import CallRecord
from gazua.runtime.worker import ExecutionContext

OBSERVATION_VERSION = 1
ENVELOPE_KEY = "gazua_observation_version"
MAX_ENVELOPE_OBSERVATIONS = 100

UnavailableReason = Literal["too_large", "not_serializable", "execution_limit"]
SinkFailure = Literal["sink_error", "sink_result_invalid"]
ResetBefore = Literal["succeeded", "failed", "absent"]

__all__ = [
    "ENVELOPE_KEY",
    "MAX_ENVELOPE_OBSERVATIONS",
    "MAX_EXECUTION_BYTES",
    "MAX_OBSERVATION_BYTES",
    "OBSERVATION_VERSION",
    "RETURNS_FILE",
    "ExecutorObservation",
    "MemoryObservation",
    "ObservationEnvelope",
    "ReturnChannel",
    "ReturnObservation",
    "SinkObservation",
    "memory_observation",
    "observe_sink",
    "output_envelope",
    "parse_envelope",
    "read_return_channel",
    "read_returns",
]


class _Observation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ReturnObservation(_Observation):
    """The private return of one tool call, correlated with the call log by ``call_seq``.

    ``original`` is what the tool returned (or the dry-run value); ``delivered`` is what reached
    the caller after injections. When the value could not be captured, only the reason exists.
    """

    model_config = ConfigDict(title="Gazua tool return observation")

    schema_version: Literal[1]
    kind: Literal["tool_return"]
    execution_id: GazuaId
    call_seq: Annotated[int, Field(ge=1)]
    original: JsonValue = None
    delivered: JsonValue = None
    unavailable_reason: UnavailableReason | None = None

    @model_validator(mode="after")
    def _content_or_reason(self) -> ReturnObservation:
        given = {"original", "delivered"} & self.model_fields_set
        if self.unavailable_reason is None and given != {"original", "delivered"}:
            raise ValueError("A captured return has both original and delivered values.")
        if self.unavailable_reason is not None and given:
            raise ValueError("An unavailable return carries no value.")
        return self


def _concrete_proof(proof: Mapping[str, JsonValue]) -> bool:
    marker = proof.get("marker_id")
    others = [value for key, value in proof.items() if key != "marker_id"]
    return (
        isinstance(marker, str)
        and bool(marker)
        and any(value not in (None, "", [], {}) for value in others)
    )


class SinkObservation(_Observation):
    """What the declared ``output_sink`` reported for one value of this execution.

    ``execution_id`` and ``kind`` are added by Gazua's helper, never taken from the sink. A
    failure keeps only its code, so the sink's messages never reach a verdict.
    """

    model_config = ConfigDict(title="Gazua output sink observation")

    schema_version: Literal[1]
    kind: Literal["sink"]
    execution_id: GazuaId
    effect: bool | None = None
    proof: dict[str, JsonValue] | None = None
    error: SinkFailure | None = None

    @model_validator(mode="after")
    def _result_or_error(self) -> SinkObservation:
        if self.error is not None:
            if self.effect is not None or self.proof is not None:
                raise ValueError("A failed sink observation carries no result.")
            return self
        if self.effect is None or self.proof is None or not _concrete_proof(self.proof):
            raise ValueError("A sink result names its marker and a concrete observation.")
        return self


class MemoryObservation(_Observation):
    """A synthetic marker written in one turn and looked up in a later turn of one session.

    Only a trusted memory adapter produces it. ``reset_before`` says the session started clean;
    ``reset_between`` says something cleared the memory between the two turns.
    """

    model_config = ConfigDict(title="Gazua memory observation")

    schema_version: Literal[1]
    kind: Literal["memory"]
    execution_id: GazuaId
    marker_id: NonEmptyText
    session_id: NonEmptyText
    write_turn: Annotated[int, Field(ge=1)]
    read_turn: Annotated[int, Field(ge=1)]
    written_value: NonEmptyText
    read_value: str
    reset_before: ResetBefore
    reset_between: bool

    @model_validator(mode="after")
    def _later_read(self) -> MemoryObservation:
        if self.read_turn <= self.write_turn:
            raise ValueError("The read happens in a turn after the write.")
        return self


ExecutorObservation = Annotated[SinkObservation | MemoryObservation, Field(discriminator="kind")]


class ObservationEnvelope(_Observation):
    """The ``output`` of an executor that uses Gazua's helpers.

    It is read as an envelope only when the attack context says the executor declares one, so
    an agent cannot produce observations by answering with this shape.
    """

    model_config = ConfigDict(title="Gazua observation envelope")

    gazua_observation_version: Literal[1]
    response: JsonValue
    observations: Annotated[
        list[ExecutorObservation], Field(max_length=MAX_ENVELOPE_OBSERVATIONS)
    ] = Field(default_factory=list[ExecutorObservation])


def output_envelope(
    response: object, observations: Sequence[Mapping[str, Any]] = ()
) -> dict[str, Any]:
    """The ``output`` an executor returns: the agent's response and Gazua's observations."""
    envelope = ObservationEnvelope.model_validate(
        {
            ENVELOPE_KEY: OBSERVATION_VERSION,
            "response": response,
            "observations": [dict(item) for item in observations],
        }
    )
    return envelope.model_dump(mode="json", exclude_unset=False)


def memory_observation(
    *,
    execution_id: str,
    marker_id: str,
    session_id: str,
    write_turn: int,
    read_turn: int,
    written_value: str,
    read_value: str,
    reset_before: ResetBefore,
    reset_between: bool,
) -> dict[str, Any]:
    """A validated memory observation, for a trusted memory adapter."""
    observation = MemoryObservation(
        schema_version=1,
        kind="memory",
        execution_id=execution_id,
        marker_id=marker_id,
        session_id=session_id,
        write_turn=write_turn,
        read_turn=read_turn,
        written_value=written_value,
        read_value=read_value,
        reset_before=reset_before,
        reset_between=reset_between,
    )
    return observation.model_dump(mode="json")


def observe_sink(
    context: ExecutionContext, value: JsonValue, *, marker_id: str
) -> dict[str, Any] | None:
    """Hands ``value`` to the declared ``output_sink`` and returns the observation to report.

    Call it from the executor, before it returns, only for the unhandled output scenario. With
    no sink declared it returns None and calls nothing in its place. A sink that fails or
    answers for another marker yields an observation with only an error code.
    """
    from gazua.runtime.hooks import SinkError, call_output_sink

    reference = getattr(context.config, "output_sink", None)
    if not isinstance(reference, str):
        return None
    head: dict[str, Any] = {
        "schema_version": OBSERVATION_VERSION,
        "kind": "sink",
        "execution_id": context.execution_id,
    }
    try:
        result = call_output_sink(reference, value)
    except SinkError as failure:
        return SinkObservation.model_validate({**head, "error": failure.code}).model_dump()
    proof = cast("dict[str, JsonValue]", result["proof"])
    try:
        if proof.get("marker_id") != marker_id:
            raise ValueError(marker_id)
        observation = SinkObservation.model_validate({**head, **result})
    except (ValueError, ValidationError):
        observation = SinkObservation.model_validate({**head, "error": "sink_result_invalid"})
    return observation.model_dump(mode="json")


def read_returns(context: ExecutionContext) -> list[dict[str, Any]]:
    """The returns captured so far in this execution, for an executor that builds its output.

    Lines that cannot be read are left out; the verdict engine checks the full sidecar again.
    """
    path = context.call_log.parent / RETURNS_FILE
    try:
        lines = path.read_bytes().split(b"\n")[:-1] if path.is_file() else []
    except OSError:
        return []
    found: list[dict[str, Any]] = []
    for raw in lines:
        try:
            observation = ReturnObservation.model_validate(
                json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
            )
        except (ValueError, ValidationError, RecursionError):
            continue
        if observation.execution_id == context.execution_id:
            found.append(observation.model_dump(mode="json", exclude_unset=True))
    return found


@dataclass(frozen=True, slots=True)
class ReturnChannel:
    """The private returns of one execution, checked against its call log.

    ``valid`` is False when a complete line is invalid or names a call that did not return; the
    whole channel is then inconclusive. ``missing`` lists returned calls without a usable value,
    which forbids a negative conclusion for signals that depend on returns.
    """

    valid: bool
    returns: Mapping[int, ReturnObservation] = field(default_factory=dict[int, ReturnObservation])
    missing: tuple[int, ...] = ()
    truncated_tail: bool = False
    reason: str | None = None

    def value(self, seq: int) -> ReturnObservation | None:
        """The captured return of call ``seq``, or None when it is not usable."""
        if not self.valid:
            return None
        found = self.returns.get(seq)
        if found is None or found.unavailable_reason is not None:
            return None
        return found


def _reject_constant(name: str) -> object:
    raise ValueError(name)


def read_return_channel(
    path: Path, execution_id: str, calls: Sequence[CallRecord], *, log_valid: bool = True
) -> ReturnChannel:
    """Reads the sidecar the wrapper wrote for one execution and correlates it with its calls."""
    returned = [call.seq for call in calls if call.outcome == "returned"]
    if not log_valid:
        return ReturnChannel(
            valid=False, missing=tuple(returned), reason="evidence_correlation_error"
        )
    try:
        content = path.read_bytes() if path.is_file() else b""
    except OSError:
        return ReturnChannel(
            valid=False, missing=tuple(returned), reason="return_observation_unavailable"
        )
    if len(content) > MAX_EXECUTION_BYTES + MAX_OBSERVATION_BYTES * 4:
        return ReturnChannel(
            valid=False, missing=tuple(returned), reason="return_observation_unavailable"
        )
    *complete, tail = content.split(b"\n")
    expected = set(returned)
    found: dict[int, ReturnObservation] = {}
    for raw in complete:
        try:
            observation = ReturnObservation.model_validate(
                json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
            )
        except (ValueError, ValidationError, RecursionError):
            return ReturnChannel(
                valid=False, missing=tuple(returned), reason="return_observation_unavailable"
            )
        seq = observation.call_seq
        if observation.execution_id != execution_id or seq not in expected or seq in found:
            return ReturnChannel(
                valid=False, missing=tuple(returned), reason="evidence_correlation_error"
            )
        found[seq] = observation
    missing = tuple(
        seq for seq in returned if seq not in found or found[seq].unavailable_reason is not None
    )
    return ReturnChannel(
        valid=True,
        returns=found,
        missing=missing,
        truncated_tail=bool(tail),
        reason="return_observation_unavailable" if missing else None,
    )


def parse_envelope(output: object) -> ObservationEnvelope | None:
    """The envelope inside an executor's output, or None when it is not a valid one."""
    if not isinstance(output, dict):
        return None
    try:
        return ObservationEnvelope.model_validate(cast("dict[str, Any]", output))
    except ValidationError:
        return None
