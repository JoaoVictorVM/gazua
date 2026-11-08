"""Run engine: prepares a plan for one target and runs each attempt in a supervised worker.

The supervisor never imports the target. Workers receive JSON, not pickled objects, and every
planned entry ends in a terminal record, including the ones that never started. A record says
how the infrastructure ended an attempt; it never says that the agent resisted.
"""

from __future__ import annotations

import contextlib
import json
import secrets
import threading
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

from gazua.config.models import GazuaConfig, Limits
from gazua.diagnostics import ConfigError, Diagnostic
from gazua.integration.channel import MAX_EVENTS
from gazua.runtime.budget import (
    Admission,
    Capacity,
    RunBudget,
    backoff_delay,
    decimal_text,
    retry_refusal,
    to_decimal,
)
from gazua.runtime.call_log import read_call_log
from gazua.runtime.evidence import (
    EvidenceStore,
    PrivateEvidence,
    Redactor,
    remove_stale_private,
    write_atomic,
)
from gazua.runtime.processes import SupervisedProcess, SupervisionError, worker_command
from gazua.runtime.receiver import ExecutionCapture, LocalReceiver
from gazua.runtime.run_models import (
    COST_WARNING,
    EXECUTION_STATUSES,
    BackoffStarted,
    BudgetWarning,
    CleanupFinished,
    CleanupOutcome,
    CostSource,
    ExecutionFinished,
    ExecutionRecord,
    ExecutionRequest,
    ExecutionStarted,
    ExecutionStatus,
    LimitOverrides,
    Progress,
    ResetOutcome,
    RunEvent,
    RunFinished,
    RunPlan,
    RunPrepared,
    RunSummary,
)
from gazua.runtime.session_models import SessionDocument
from gazua.runtime.session_writer import SessionExecution, build_session, write_session
from gazua.runtime.tools import ToolSummary

POLL_SECONDS = 0.02
EVENT_KINDS = frozenset(
    {"tool_call_admitted", "tool_call_ceiling", "usage", "reset_started", "reset_before"}
)

EventCallback = Callable[[RunEvent], None]
EvidenceCallback = Callable[[ExecutionRecord, PrivateEvidence], None]


def _failure(code: str, message: str, field: str | None = None) -> ConfigError:
    return ConfigError([Diagnostic(code=code, field=field, message=message)])


def _new_run_id() -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    return f"GAZUA-run-{stamp}-{secrets.token_hex(3)}"


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def effective_limits(config: GazuaConfig, overrides: LimitOverrides | None) -> Limits:
    """Configured limits with every override that was given in their place."""
    values = config.limits.model_dump()
    if overrides is not None:
        values.update(overrides.model_dump(exclude_none=True))
    return Limits.model_validate(values)


def cost_source(limits: Limits, requests: Sequence[ExecutionRequest]) -> CostSource:
    """The estimate governs admission when declared; reported usage counts only without it."""
    if limits.cost_per_run is not None:
        return "estimated"
    if any(request.usage_reporting for request in requests):
        return "reported"
    return "unavailable"


def prepare_run(
    config: GazuaConfig,
    requests: Sequence[ExecutionRequest],
    overrides: LimitOverrides | None = None,
    *,
    project_root: Path,
    run_id: str | None = None,
) -> RunPlan:
    """Validates one target, its references and requests, without importing anything."""
    if not isinstance(config, GazuaConfig):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise _failure("multiple_targets", "A run tests exactly one target configuration.")
    if config.entrypoint is None and any(request.mode == "agent" for request in requests):
        raise _failure("entrypoint_missing", "Agent executions need an entrypoint.", "entrypoint")
    items = tuple(requests)
    if not items:
        raise _failure("empty_plan", "A run needs at least one execution.")
    keys = [request.key for request in items]
    if len(set(keys)) != len(keys):
        raise _failure("duplicate_request", "Each execution needs a unique key.", "requests")
    limits = effective_limits(config, overrides)
    root = project_root.resolve()
    if not root.is_dir():
        raise _failure("project_root", "The project folder does not exist.")
    identifier = run_id if run_id is not None else _new_run_id()
    valid = identifier.isascii() and identifier.replace("-", "").isalnum()
    if not identifier.startswith("GAZUA-run-") or not valid:
        raise _failure(
            "run_id", "Run identifiers start with GAZUA-run- and use letters, digits and hyphens."
        )
    return RunPlan(
        run_id=identifier,
        config=config,
        project_root=root,
        engine_root=root / ".gazua" / "runs" / identifier / "engine",
        requests=items,
        limits=limits,
        effective_concurrency=1 if config.target.reset is not None else limits.concurrency,
        cost_source=cost_source(limits, items),
    )


@dataclass(slots=True)
class _Pending:
    request: ExecutionRequest
    attempt: int = 1


@dataclass(slots=True)
class _Active:
    pending: _Pending
    execution_id: str
    process: SupervisedProcess
    work: Path
    started_clock: float
    started_at: str
    deadline: float
    estimate: Decimal | None
    receiver: bool
    events_offset: int = 0
    events_buffer: bytes = b""
    next_seq: int = 1
    admitted: int = 0
    ceiling: bool = False
    reset_started: bool = False
    reset_outcome: str | None = None
    usage: dict[str, Decimal] = field(default_factory=dict[str, Decimal])
    protocol_errors: list[str] = field(default_factory=list[str])


@dataclass(frozen=True, slots=True)
class _Outcome:
    status: ExecutionStatus
    reason: str | None


class _Run:
    def __init__(
        self,
        plan: RunPlan,
        on_event: EventCallback | None,
        on_evidence: EvidenceCallback | None,
        cancel: threading.Event | None,
    ) -> None:
        self.plan = plan
        self.config = plan.config
        self.limits = plan.limits
        self.on_event = on_event
        self.on_evidence = on_evidence
        self.cancel = cancel
        self.seq = 0
        self.execution_number = 0
        self.pending: deque[_Pending] = deque(_Pending(item) for item in plan.requests)
        self.active: dict[str, _Active] = {}
        self.records: list[ExecutionRecord] = []
        self.recorded: set[str] = set()
        self.resolved: set[str] = set()
        self.retries = 0
        self.admission_open = True
        self.paused_until = 0.0
        self.interrupted = False
        self.usage_incomplete = False
        self.cost_warned = False
        self.cleanup: CleanupOutcome = "absent"
        self.operational_errors: list[str] = []
        self.budget = RunBudget(
            max_runs=self.limits.max_runs,
            max_cost=None if self.limits.max_cost is None else to_decimal(self.limits.max_cost),
            cost_per_run=None
            if self.limits.cost_per_run is None
            else to_decimal(self.limits.cost_per_run),
            source=plan.cost_source,
        )
        self.capacity = Capacity(plan.effective_concurrency)
        self.store = EvidenceStore(
            plan.project_root, plan.engine_root, Redactor(self.config.canaries)
        )
        self.receiver: LocalReceiver | None = None

    def emit(self, event: RunEvent) -> None:
        if self.on_event is not None:
            self.on_event(event)

    def next_seq(self) -> int:
        self.seq += 1
        return self.seq

    def new_execution_id(self) -> str:
        self.execution_number += 1
        return f"GAZUA-exec-{self.execution_number:04d}"

    def progress(self) -> Progress:
        started = sum(record.started_at is not None for record in self.records)
        return Progress(
            planned=len(self.plan.requests),
            resolved=len(self.resolved),
            started=self.budget.started,
            active=len(self.active),
            finished=started,
            not_started=len(self.records) - started,
            retries=self.retries,
        )

    def error(self, code: str) -> None:
        if code not in self.operational_errors:
            self.operational_errors.append(code)

    def worker(self, job: dict[str, Any], folder: Path) -> SupervisedProcess:
        job_path = folder / "job.json"
        write_atomic(job_path, json.dumps(job, ensure_ascii=True))
        process = SupervisedProcess(worker_command(str(job_path)), self.plan.project_root)
        process.start()
        return process

    def base_job(self, kind: str, folder: Path, session: Path | None) -> dict[str, Any]:
        return {
            "kind": kind,
            "session": None if session is None else str(session),
            "result": str(folder / "result.json"),
            "project_root": str(self.plan.project_root),
            "reset": self.config.target.reset,
            "entrypoint": self.config.entrypoint,
            "config": self.config.to_document(),
            "run_id": self.plan.run_id,
        }

    def wait(self, process: SupervisedProcess, timeout: float) -> int | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            code = process.poll()
            if code is not None:
                return code
            time.sleep(POLL_SECONDS)
        return None

    def read_result(self, folder: Path) -> dict[str, Any] | None:
        try:
            document = json.loads((folder / "result.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return cast("dict[str, Any]", document) if isinstance(document, dict) else None

    # Preparation

    def preflight(self) -> ToolSummary | None:
        """The tool inventory, read in an isolated worker with every tool in dry-run."""
        if self.config.entrypoint is None:
            return None
        folder = self.store.working_directory("GAZUA-preflight")
        session = build_session(self.config, run_id=self.plan.run_id, mode="agent")
        forced = SessionDocument.model_validate(
            {
                **session.model_dump(),
                "tools": {
                    name: tool.model_copy(update={"dry_run": True})
                    for name, tool in session.tools.items()
                },
            }
        )
        written = write_session(forced, folder)
        try:
            process = self.worker(self.base_job("preflight", folder, written.path), folder)
        except (SupervisionError, OSError):
            raise _failure(
                "supervision_unavailable", "The worker process could not be supervised."
            ) from None
        code = self.wait(process, self.limits.timeout)
        if code is None:
            process.kill_tree()
        process.close()
        result = self.read_result(folder)
        self.store.discard("GAZUA-preflight")
        if code is None or result is None or result.get("status") != "ok":
            reason = "timeout" if code is None else str((result or {}).get("code", "crashed"))
            raise _failure(
                "preflight_failed",
                f"The target could not be loaded for the tool inventory ({reason}).",
                "entrypoint",
            )
        tools = cast("dict[str, Any]", result["tools"])
        return ToolSummary(
            real=tuple(tools["real"]),
            dry_run=tuple(tools["dry_run"]),
            low_fidelity=tuple(tools["low_fidelity"]),
            warnings=tuple(
                Diagnostic(
                    code=item["code"],
                    field=item["field"],
                    message=item["message"],
                    severity="warning",
                )
                for item in tools["warnings"]
            ),
        )

    def prepared_event(self, tools: ToolSummary | None) -> RunPrepared:
        molds = {request.mold_id for request in self.plan.requests}
        per_mold: dict[str, int] = {}
        for request in self.plan.requests:
            per_mold[request.mold_id] = per_mold.get(request.mold_id, 0) + 1
        counts = set(per_mold.values())
        warnings: list[str] = []
        if self.limits.max_cost is not None and self.plan.cost_source == "unavailable":
            warnings.append(COST_WARNING)
            self.cost_warned = True
        return RunPrepared(
            seq=self.next_seq(),
            planned=len(self.plan.requests),
            molds=len(molds),
            repetitions=counts.pop() if len(counts) == 1 else None,
            max_runs=self.limits.max_runs,
            max_retries=self.plan.max_retries,
            requested_concurrency=self.plan.requested_concurrency,
            effective_concurrency=self.plan.effective_concurrency,
            tools=tools,
            cost_source=self.plan.cost_source,
            warnings=tuple(warnings),
        )

    # Records

    def record(
        self,
        pending: _Pending,
        execution_id: str,
        outcome: _Outcome,
        *,
        final: bool = True,
        **fields: Any,
    ) -> ExecutionRecord:
        values: dict[str, Any] = {
            "schema_version": 1,
            "run_id": self.plan.run_id,
            "execution_id": execution_id,
            "request_key": pending.request.key,
            "mold_id": pending.request.mold_id,
            "repetition": pending.request.repetition,
            "attempt": pending.attempt,
            "status": outcome.status,
            "reason": outcome.reason,
            "started_at": None,
            "finished_at": None,
            "duration_ms": None,
            "exit_code": None,
            "admitted_tool_calls": 0,
            "evidence_complete": False,
            "truncated_tail": False,
            "reported_cost_usd": None,
            "estimated_cost_usd": None,
            "usage_complete": False,
            "call_log": None,
            "receiver_hits": None,
            "output": None,
            "reset_before": "not_started",
        }
        values.update(fields)
        record = ExecutionRecord.model_validate(values)
        self.records.append(record)
        self.recorded.add(execution_id)
        if final:
            self.resolved.add(pending.request.key)
        folder = self.store.public_directory(execution_id)
        write_atomic(folder / "execution.json", record.model_dump_json(indent=2) + "\n")
        return record

    def not_started(self, pending: _Pending, outcome: _Outcome) -> None:
        record = self.record(pending, self.new_execution_id(), outcome)
        self.emit(ExecutionFinished(seq=self.next_seq(), record=record, progress=self.progress()))

    def close_admission(self, outcome: _Outcome) -> None:
        """No more attempts start. Every pending entry gets its record now."""
        self.admission_open = False
        while self.pending:
            self.not_started(self.pending.popleft(), outcome)
        self.snapshot()

    def cost_warning(self) -> None:
        if not self.cost_warned and self.limits.max_cost is not None:
            self.cost_warned = True
            self.emit(
                BudgetWarning(seq=self.next_seq(), reason="cost_unavailable", message=COST_WARNING)
            )

    # Launch

    def launch_ready(self) -> None:
        while (
            self.admission_open
            and self.pending
            and len(self.active) < self.capacity.value
            and time.monotonic() >= self.paused_until
        ):
            item = self.pending[0]
            request = item.request
            if request.requires_receiver and (not request.receiver_transport or not self.receiver):
                self.pending.popleft()
                self.not_started(item, _Outcome("not_tested", "receiver_unavailable"))
                continue
            admission = self.budget.reserve()
            if not isinstance(admission, Admission):
                self.close_admission(_Outcome("skipped_by_limit", admission))
                if admission == "max_cost":
                    self.emit(
                        BudgetWarning(
                            seq=self.next_seq(),
                            reason="max_cost",
                            message="max_cost reached; remaining executions are not tested.",
                        )
                    )
                return
            self.pending.popleft()
            self.launch(item, admission)

    def launch(self, item: _Pending, admission: Admission) -> None:
        execution_id = self.new_execution_id()
        request = item.request
        folder = self.store.working_directory(execution_id)
        receiver = None
        if self.receiver is not None and request.receiver_transport:
            receiver = self.receiver.register(execution_id)
        session = build_session(
            self.config,
            run_id=self.plan.run_id,
            mode=request.mode,
            actor=request.actor,
            injections=request.injections,
            execution=SessionExecution(
                execution_id=execution_id,
                max_tool_calls=self.limits.max_tool_calls,
                receiver=receiver,
                usage_reporting=request.usage_reporting,
            ),
        )
        written = write_session(session, folder)
        job = {
            **self.base_job("attack", folder, written.path),
            "execution_id": execution_id,
            "executor": request.executor,
            "request": request.model_dump(mode="json"),
            "directory": str(folder),
            "call_log": str(written.call_log),
        }
        started_at, clock = _utc_now(), time.monotonic()
        try:
            process = self.worker(job, folder)
        except (SupervisionError, OSError):
            if self.receiver is not None:
                self.receiver.close_execution(execution_id)
            self.record(
                item,
                execution_id,
                _Outcome("crashed", "supervision_unavailable"),
                started_at=started_at,
                finished_at=_utc_now(),
                duration_ms=0,
                estimated_cost_usd=None
                if admission.estimate is None
                else decimal_text(admission.estimate),
            )
            self.store.discard(execution_id)
            self.error("supervision_unavailable")
            self.close_admission(_Outcome("not_tested", "supervision_unavailable"))
            return
        self.active[execution_id] = _Active(
            pending=item,
            execution_id=execution_id,
            process=process,
            work=folder,
            started_clock=clock,
            started_at=started_at,
            deadline=clock + self.limits.timeout,
            estimate=admission.estimate,
            receiver=receiver is not None,
        )
        self.emit(
            ExecutionStarted(
                seq=self.next_seq(),
                execution_id=execution_id,
                request_key=request.key,
                attempt=item.attempt,
                progress=self.progress(),
            )
        )

    # Supervision

    def read_events(self, active: _Active) -> None:
        path = active.work / "events.jsonl"
        try:
            with path.open("rb") as handle:
                handle.seek(active.events_offset)
                chunk = handle.read()
        except FileNotFoundError:
            return
        except OSError:
            active.protocol_errors.append("execution_protocol_error")
            return
        active.events_offset += len(chunk)
        *lines, active.events_buffer = (active.events_buffer + chunk).split(b"\n")
        for line in lines:
            self.apply_event(active, line)

    def apply_event(self, active: _Active, line: bytes) -> None:
        try:
            event = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            active.protocol_errors.append("execution_protocol_error")
            return
        if (
            not isinstance(event, dict)
            or cast("dict[str, Any]", event).get("schema_version") != 1
            or cast("dict[str, Any]", event).get("execution_id") != active.execution_id
        ):
            active.protocol_errors.append("execution_protocol_error")
            return
        data = cast("dict[str, Any]", event)
        seq, kind, payload = data.get("seq"), data.get("kind"), data.get("payload")
        if seq != active.next_seq or kind not in EVENT_KINDS or not isinstance(payload, dict):
            active.protocol_errors.append("execution_protocol_error")
            return
        active.next_seq += 1
        if active.next_seq > MAX_EVENTS + 1:
            active.protocol_errors.append("execution_protocol_error")
        values = cast("dict[str, Any]", payload)
        if kind == "tool_call_admitted" and type(values.get("count")) is int:
            active.admitted = max(active.admitted, values["count"])
        elif kind == "tool_call_ceiling":
            active.ceiling = True
        elif kind == "reset_started":
            active.reset_started = True
        elif kind == "reset_before" and values.get("outcome") in ("succeeded", "failed"):
            active.reset_outcome = values["outcome"]
        elif kind == "usage":
            self.apply_usage(active, values)

    def apply_usage(self, active: _Active, values: dict[str, Any]) -> None:
        usage_id, cost = values.get("usage_id"), values.get("cost_usd")
        try:
            if not isinstance(usage_id, str) or not isinstance(cost, str):
                raise ValueError(cost)
            amount = to_decimal(cost)
        except ValueError:
            active.protocol_errors.append("execution_protocol_error")
            return
        if usage_id not in active.usage:
            active.usage[usage_id] = amount
            self.budget.record_usage(f"{active.execution_id}:{usage_id}", amount)

    def supervise(self) -> None:
        for active in list(self.active.values()):
            self.read_events(active)
            code = active.process.poll()
            if active.ceiling:
                self.finish(active, _Outcome("killed_at_ceiling", "tool_call_ceiling"))
            elif code is not None:
                self.finish(active, None)
            elif time.monotonic() > active.deadline:
                in_reset = active.reset_started and active.reset_outcome is None
                outcome = (
                    _Outcome("reset_failed", "reset_failed")
                    if in_reset
                    else _Outcome("timed_out", "attack_timeout")
                )
                self.finish(active, outcome)
        if self.budget.reported_exhausted and (self.admission_open or self.active):
            self.emit(
                BudgetWarning(
                    seq=self.next_seq(),
                    reason="max_cost",
                    message="max_cost reached by reported usage; work in flight may exceed it.",
                )
            )
            self.cancel_active(_Outcome("cancelled", "max_cost"))
            self.close_admission(_Outcome("skipped_by_limit", "max_cost"))

    def cancel_active(self, outcome: _Outcome) -> None:
        for active in list(self.active.values()):
            self.finish(active, outcome)

    def finish(self, active: _Active, forced: _Outcome | None) -> None:
        """Ends one attempt: kills what is left, collects evidence and writes its record."""
        if active.execution_id in self.recorded:
            self.active.pop(active.execution_id, None)
            return
        process = active.process
        exit_code = process.poll()
        if forced is not None and exit_code is None:
            if not process.kill_tree():
                self.error("cleanup_failed")
            exit_code = process.poll()
        stdout, stderr = process.close()
        if process.kill_failed:
            self.error("cleanup_failed")
        self.read_events(active)
        finished_clock, finished_at = time.monotonic(), _utc_now()
        capture = (
            self.receiver.close_execution(active.execution_id)
            if self.receiver is not None and active.receiver
            else ExecutionCapture((), ())
        )
        result = None if forced is not None else self.read_result(active.work)
        raw_lines, records, truncated, log_valid = self.call_log(active)
        outcome, retry = self.outcome(active, forced, result, records, len(raw_lines))
        reset_before = self.reset_before(active, forced)
        request = active.pending.request
        usage_complete = bool(result and result.get("usage_complete") is True and active.usage)
        if request.usage_reporting and not usage_complete:
            self.usage_incomplete = True
            self.cost_warning()
        complete = (
            forced is None
            and result is not None
            and log_valid
            and not truncated
            and not active.protocol_errors
            and not capture.coverage_errors
        )
        output = result.get("output") if result is not None else None
        evidence = PrivateEvidence(
            execution_id=active.execution_id,
            calls=records,
            truncated_tail=truncated,
            receiver_hits=capture.hits,
            output=output,
            stdout=stdout,
            stderr=stderr,
            complete=complete,
        )
        references = self.store.persist(evidence, raw_lines if log_valid else [])
        reported = sum(active.usage.values(), Decimal(0)) if active.usage else None
        record = self.record(
            active.pending,
            active.execution_id,
            outcome,
            final=retry is None,
            started_at=active.started_at,
            finished_at=finished_at,
            duration_ms=int((finished_clock - active.started_clock) * 1000),
            exit_code=exit_code,
            admitted_tool_calls=max(active.admitted, len(records)),
            evidence_complete=complete,
            truncated_tail=truncated,
            reported_cost_usd=None if reported is None else decimal_text(reported),
            estimated_cost_usd=None if active.estimate is None else decimal_text(active.estimate),
            usage_complete=usage_complete,
            call_log=references.call_log,
            receiver_hits=references.receiver_hits,
            output=references.output,
            reset_before=reset_before,
        )
        self.active.pop(active.execution_id, None)
        try:
            if self.on_evidence is not None:
                self.on_evidence(record, evidence)
        finally:
            self.store.discard(active.execution_id)
        self.emit(ExecutionFinished(seq=self.next_seq(), record=record, progress=self.progress()))
        if retry is not None:
            self.schedule_retry(active.pending, retry)
        if outcome.status == "reset_failed":
            self.error("reset_failed")
            self.cancel_active(_Outcome("cancelled", "reset_failed"))
            self.close_admission(_Outcome("reset_failed", "reset_failed"))
        self.snapshot()

    def call_log(self, active: _Active) -> tuple[list[str], tuple[Any, ...], bool, bool]:
        path = active.work / "calls.jsonl"
        if not path.is_file():
            return [], (), False, True
        content = path.read_bytes()
        *complete, tail = content.split(b"\n")
        try:
            reading = read_call_log(path)
        except ConfigError:
            return [], (), bool(tail), False
        lines = [line.decode("utf-8") for line in complete]
        return lines, reading.records, reading.truncated_tail, True

    def outcome(
        self,
        active: _Active,
        forced: _Outcome | None,
        result: dict[str, Any] | None,
        records: tuple[Any, ...],
        logged: int,
    ) -> tuple[_Outcome, float | None]:
        """The terminal status and, for a retried 429, the requested wait."""
        if forced is not None:
            return forced, None
        if result is None:
            return _Outcome("crashed", "agent_crashed"), None
        status = result.get("status")
        if status == "ok":
            return _Outcome("completed", None), None
        if status == "reset_failed":
            return _Outcome("reset_failed", "reset_failed"), None
        if status == "rate_limited":
            self.capacity.halve()
            real = any(not record.dry_run and record.outcome != "blocked" for record in records)
            # A slot admitted without a finished record may have run for real.
            dirty = real or active.admitted > logged
            refusal = retry_refusal(
                attempt=active.pending.attempt,
                max_retries=self.plan.max_retries,
                real_tool_called=dirty,
                has_reset=self.config.target.reset is not None,
            )
            if refusal is not None or not self.admission_open:
                return _Outcome("rate_limited", refusal or "rate_limited"), None
            retry_after = result.get("retry_after")
            wait = backoff_delay(
                active.pending.attempt - 1,
                float(retry_after) if isinstance(retry_after, int | float) else None,
            )
            return _Outcome("rate_limited", "rate_limited"), wait
        code = result.get("code")
        if code in ("entrypoint_error", "executor_error", "blocked"):
            return _Outcome("crashed", "agent_crashed"), None
        return _Outcome("crashed", "execution_protocol_error"), None

    def reset_before(self, active: _Active, forced: _Outcome | None) -> ResetOutcome:
        if self.config.target.reset is None:
            return "absent"
        if active.reset_outcome in ("succeeded", "failed"):
            return cast("ResetOutcome", active.reset_outcome)
        if active.reset_started:
            return "timed_out" if forced is not None else "failed"
        return "not_started"

    def schedule_retry(self, pending: _Pending, wait: float) -> None:
        self.retries += 1
        self.paused_until = max(self.paused_until, time.monotonic() + wait)
        self.pending.appendleft(_Pending(pending.request, pending.attempt + 1))
        self.emit(
            BackoffStarted(
                seq=self.next_seq(),
                request_key=pending.request.key,
                delay_seconds=wait,
                capacity=self.capacity.value,
            )
        )

    # Finalization

    def final_reset(self) -> None:
        """Runs ``target.reset`` once more in its own worker, within the attack timeout."""
        reference = self.config.target.reset
        if reference is None:
            self.cleanup = "absent"
            return
        folder = self.store.working_directory("GAZUA-cleanup")
        session = build_session(self.config, run_id=self.plan.run_id, mode="agent")
        written = write_session(session, folder)
        try:
            process = self.worker(self.base_job("reset", folder, written.path), folder)
        except (SupervisionError, OSError):
            self.cleanup = "failed"
            self.error("cleanup_failed")
            return
        try:
            code = self.wait(process, self.limits.timeout)
        except KeyboardInterrupt:
            process.kill_tree()
            process.close()
            self.cleanup = "aborted"
            self.error("cleanup_aborted")
            return
        if code is None:
            if not process.kill_tree():
                self.error("cleanup_failed")
            process.close()
            self.cleanup = "timed_out"
            self.error("cleanup_failed")
            return
        process.close()
        result = self.read_result(folder)
        succeeded = result is not None and result.get("status") == "ok"
        self.cleanup = "succeeded" if succeeded else "failed"
        if not succeeded:
            self.error("cleanup_failed")

    def interrupt(self) -> None:
        """First Ctrl+C: no more attempts, active ones are killed, pending ones not tested."""
        self.interrupted = True
        self.admission_open = False
        self.cancel_active(_Outcome("cancelled", "interrupted"))
        self.close_admission(_Outcome("not_tested", "interrupted"))

    def summary(self) -> RunSummary:
        counts = dict.fromkeys(EXECUTION_STATUSES, 0)
        for record in self.records:
            counts[record.status] += 1
        source = self.plan.cost_source
        if source == "estimated":
            coverage = "complete"
        elif source == "reported":
            coverage = "incomplete" if self.usage_incomplete else "complete"
        else:
            coverage = "incomplete" if self.limits.max_cost is not None else "not_applicable"
        return RunSummary(
            schema_version=1,
            run_id=self.plan.run_id,
            interrupted=self.interrupted,
            limits=self.limits,
            requested_concurrency=self.plan.requested_concurrency,
            effective_concurrency=self.plan.effective_concurrency,
            planned=len(self.plan.requests),
            started=self.budget.started,
            retries=self.retries,
            counts=counts,
            cost_source=source,
            cost_coverage=coverage,
            budget_guaranteed=self.limits.max_cost is not None and source == "estimated",
            reserved_estimate_usd=None
            if self.budget.cost_per_run is None
            else decimal_text(self.budget.reserved),
            reported_cost_usd=decimal_text(self.budget.reported)
            if any(record.reported_cost_usd is not None for record in self.records)
            else None,
            cleanup=self.cleanup,
            operational_errors=list(self.operational_errors),
            records=list(self.records),
        )

    def snapshot(self) -> RunSummary:
        summary = self.summary()
        write_atomic(self.plan.engine_root / "summary.json", summary.model_dump_json(indent=2))
        return summary

    def loop(self) -> None:
        while True:
            if self.cancel is not None and self.cancel.is_set():
                raise KeyboardInterrupt
            self.supervise()
            self.launch_ready()
            if not self.active and not self.pending:
                return
            time.sleep(POLL_SECONDS)

    def execute(self) -> RunSummary:
        remove_stale_private(self.plan.project_root / ".gazua" / "runs")
        self.store.open()
        try:
            tools = self.preflight()
            self.emit(self.prepared_event(tools))
            if any(request.receiver_transport for request in self.plan.requests):
                receiver = LocalReceiver(self.plan.run_id)
                try:
                    receiver.start()
                except OSError:
                    self.error("receiver_unavailable")
                else:
                    self.receiver = receiver
            try:
                self.loop()
            except KeyboardInterrupt:
                self.interrupt()
            try:
                self.final_reset()
            except KeyboardInterrupt:
                self.cleanup = "aborted"
                self.error("cleanup_aborted")
            summary = self.snapshot()
            self.emit(CleanupFinished(seq=self.next_seq(), outcome=self.cleanup))
            self.emit(RunFinished(seq=self.next_seq(), summary=summary))
            return summary
        finally:
            for active in list(self.active.values()):
                with contextlib.suppress(Exception):
                    active.process.kill_tree()
                    active.process.close()
            if self.receiver is not None:
                self.receiver.stop()
            self.store.close()


def execute_plan(
    plan: RunPlan,
    on_event: EventCallback | None = None,
    *,
    on_evidence: EvidenceCallback | None = None,
    cancel: threading.Event | None = None,
) -> RunSummary:
    """Runs a prepared plan and returns its infrastructure summary.

    ``on_event`` is called in order; ``run_prepared`` comes first and no attack starts before it
    returns. ``on_evidence`` receives the raw evidence of each attempt, which is deleted when it
    returns. Ctrl+C, or setting ``cancel``, stops new attempts, kills active ones, runs the final
    reset and still returns a partial summary with ``interrupted`` set.
    """
    return _Run(plan, on_event, on_evidence, cancel).execute()
