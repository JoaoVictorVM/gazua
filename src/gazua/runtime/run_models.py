"""Contracts of the run engine: requests, plan, events, execution records and the run summary.

A record says how an execution ended for the infrastructure (finished, timed out, killed at the
tool call ceiling, not started). It never says whether the agent resisted an attack: that is the
verdict engine's decision, made from the evidence these records point to.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from gazua.config.models import (
    SCHEMA_DIALECT,
    GazuaConfig,
    Limits,
    NonNegativeNumber,
    PositiveInt,
    PositiveNumber,
    Reference,
)
from gazua.runtime.session_models import SessionInjection

if TYPE_CHECKING:
    from gazua.runtime.tools import ToolSummary

EXECUTION_SCHEMA_FILE = "execution-v1.schema.json"
RECEIVER_HIT_SCHEMA_FILE = "receiver-hit-v1.schema.json"
_SCHEMA_BASE = "https://raw.githubusercontent.com/JoaoVictorVM/gazua/main/src/gazua/schemas/"
MAX_RETRIES = 2
COST_WARNING = "Warning: max_cost does not apply without reported usage or cost_per_run."

NonEmptyText = Annotated[str, Field(min_length=1)]
GazuaId = Annotated[str, Field(pattern=r"^GAZUA-[A-Za-z0-9-]+$")]
DecimalText = Annotated[str, Field(pattern=r"^(0|[1-9][0-9]*)(\.[0-9]+)?$")]
UtcTimestamp = Annotated[
    str, Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$")
]
LocalReference = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-][A-Za-z0-9._/-]*$")]

ExecutionStatus = Literal[
    "completed",
    "timed_out",
    "killed_at_ceiling",
    "skipped_by_limit",
    "crashed",
    "reset_failed",
    "rate_limited",
    "cancelled",
    "not_tested",
]
EXECUTION_STATUSES: tuple[ExecutionStatus, ...] = (
    "completed",
    "timed_out",
    "killed_at_ceiling",
    "skipped_by_limit",
    "crashed",
    "reset_failed",
    "rate_limited",
    "cancelled",
    "not_tested",
)
ResetOutcome = Literal["absent", "succeeded", "failed", "timed_out", "not_started"]
CostSource = Literal["estimated", "reported", "unavailable"]
CleanupOutcome = Literal["absent", "succeeded", "failed", "timed_out", "aborted"]
LogicalMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class LimitOverrides(_Contract):
    """Limits a consumer's flags set for one run. Each one replaces the configured value."""

    max_runs: PositiveInt | None = None
    timeout: PositiveNumber | None = None
    max_tool_calls: PositiveInt | None = None
    concurrency: PositiveInt | None = None
    max_cost: PositiveNumber | None = None
    cost_per_run: NonNegativeNumber | None = None


class ExecutionRequest(_Contract):
    """One execution prepared by a mode. The engine runs it and never interprets it.

    ``executor`` is the consumer's own code, resolved inside the worker; it never comes from a
    mold. ``receiver_transport`` and ``usage_reporting`` are what the test entrypoint declares.
    """

    key: NonEmptyText
    mold_id: NonEmptyText
    repetition: PositiveInt
    mode: Literal["tools", "agent"]
    executor: Reference
    payload: dict[str, JsonValue]
    requires_receiver: bool
    receiver_transport: bool
    usage_reporting: bool
    actor: Literal["attacker", "victim"] | None = None
    injections: list[SessionInjection] = Field(default_factory=list[SessionInjection])


class ExecutionRecord(_Contract):
    """How one planned execution ended. Exactly one exists per attempt and per unstarted entry."""

    model_config = ConfigDict(title="Gazua execution record")

    schema_version: Literal[1]
    run_id: GazuaId
    execution_id: GazuaId
    request_key: NonEmptyText
    mold_id: NonEmptyText
    repetition: PositiveInt
    attempt: PositiveInt
    status: ExecutionStatus
    reason: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$")] | None
    started_at: UtcTimestamp | None
    finished_at: UtcTimestamp | None
    duration_ms: Annotated[int, Field(ge=0)] | None
    exit_code: int | None
    admitted_tool_calls: Annotated[int, Field(ge=0)]
    evidence_complete: bool
    truncated_tail: bool
    reported_cost_usd: DecimalText | None
    estimated_cost_usd: DecimalText | None
    usage_complete: bool
    call_log: LocalReference | None
    receiver_hits: LocalReference | None
    output: LocalReference | None
    reset_before: ResetOutcome


class ReceiverHit(_Contract):
    """One request that reached the local receiver, correlated by the worker's channel only."""

    model_config = ConfigDict(title="Gazua receiver hit")

    schema_version: Literal[1]
    hit_id: NonEmptyText
    run_id: GazuaId
    execution_id: GazuaId
    received_at: UtcTimestamp
    method: LogicalMethod
    logical_url: NonEmptyText
    body_size: Annotated[int, Field(ge=0)]
    truncated: bool
    evidence: LocalReference | None


class RunSummary(_Contract):
    """The infrastructure result of a run, also written when it was interrupted."""

    schema_version: Literal[1]
    run_id: GazuaId
    interrupted: bool
    limits: Limits
    requested_concurrency: PositiveInt
    effective_concurrency: PositiveInt
    planned: Annotated[int, Field(ge=0)]
    started: Annotated[int, Field(ge=0)]
    retries: Annotated[int, Field(ge=0)]
    counts: dict[ExecutionStatus, Annotated[int, Field(ge=0)]]
    cost_source: CostSource
    cost_coverage: Literal["complete", "incomplete", "not_applicable"]
    budget_guaranteed: bool
    reserved_estimate_usd: DecimalText | None
    reported_cost_usd: DecimalText | None
    cleanup: CleanupOutcome
    operational_errors: list[NonEmptyText]
    records: list[ExecutionRecord]


@dataclass(frozen=True, slots=True)
class RunPlan:
    """A finite, ordered and immutable plan for one target. Nothing was imported to build it."""

    run_id: str
    config: GazuaConfig
    project_root: Path
    engine_root: Path
    requests: tuple[ExecutionRequest, ...]
    limits: Limits
    effective_concurrency: int
    cost_source: CostSource
    max_retries: int = MAX_RETRIES

    @property
    def requested_concurrency(self) -> int:
        return self.limits.concurrency


@dataclass(frozen=True, slots=True)
class Progress:
    """Counters shown by the live counter. They never carry attack text."""

    planned: int
    resolved: int
    started: int
    active: int
    finished: int
    not_started: int
    retries: int

    @property
    def text(self) -> str:
        return (
            f"[{self.resolved}/{self.planned}] started {self.started}, active {self.active}, "
            f"finished {self.finished}, not run {self.not_started}, retries {self.retries}"
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class RunEvent:
    seq: int
    kind: str = ""


@dataclass(frozen=True, slots=True, kw_only=True)
class RunPrepared(RunEvent):
    """What a run shows before its first attack. The engine waits for this callback."""

    kind: str = "run_prepared"
    planned: int
    molds: int
    repetitions: int | None
    max_runs: int
    max_retries: int
    requested_concurrency: int
    effective_concurrency: int
    tools: ToolSummary | None
    cost_source: CostSource
    warnings: tuple[str, ...] = ()

    def lines(self) -> list[str]:
        shape = f"{self.molds} mold" + ("" if self.molds == 1 else "s")
        if self.repetitions is not None:
            shape += f" x {self.repetitions} repetition" + ("" if self.repetitions == 1 else "s")
        head = f"Running {self.planned} executions: {shape}. Limit {self.max_runs}."
        if self.tools is not None:
            head += f" {self.tools.text}."
        lines = [head]
        serialized = self.effective_concurrency < self.requested_concurrency
        lines.append(
            f"Concurrency {self.effective_concurrency}"
            + (
                f" (requested {self.requested_concurrency}, target.reset runs one at a time)."
                if serialized
                else "."
            )
        )
        lines.append(
            f"Retries after a reported 429: up to {self.max_retries} per execution, "
            f"counted in the limit of {self.max_runs}."
        )
        if self.tools is not None:
            lines.extend(self.tools.lines()[1:])
        lines.extend(self.warnings)
        return lines


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionStarted(RunEvent):
    kind: str = "execution_started"
    execution_id: str
    request_key: str
    attempt: int
    progress: Progress


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionFinished(RunEvent):
    kind: str = "execution_finished"
    record: ExecutionRecord
    progress: Progress


@dataclass(frozen=True, slots=True, kw_only=True)
class BudgetWarning(RunEvent):
    kind: str = "budget_warning"
    reason: str
    message: str


@dataclass(frozen=True, slots=True, kw_only=True)
class BackoffStarted(RunEvent):
    kind: str = "backoff"
    request_key: str
    delay_seconds: float
    capacity: int


@dataclass(frozen=True, slots=True, kw_only=True)
class CleanupFinished(RunEvent):
    kind: str = "cleanup_finished"
    outcome: CleanupOutcome


@dataclass(frozen=True, slots=True, kw_only=True)
class RunFinished(RunEvent):
    kind: str = "run_finished"
    summary: RunSummary


def _schema(model: type[BaseModel], name: str) -> dict[str, Any]:
    schema = model.model_json_schema(mode="validation")
    return {"$schema": SCHEMA_DIALECT, "$id": _SCHEMA_BASE + name, **schema}


def build_execution_json_schema() -> dict[str, Any]:
    return _schema(ExecutionRecord, EXECUTION_SCHEMA_FILE)


def build_receiver_hit_json_schema() -> dict[str, Any]:
    return _schema(ReceiverHit, RECEIVER_HIT_SCHEMA_FILE)


def render_execution_json_schema() -> str:
    return json.dumps(build_execution_json_schema(), indent=2) + "\n"


def render_receiver_hit_json_schema() -> str:
    return json.dumps(build_receiver_hit_json_schema(), indent=2) + "\n"
