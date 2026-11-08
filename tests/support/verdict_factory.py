"""Synthetic contexts, records and evidence for verdict engine tests.

Every value is built from validated models, the same way the run engine produces them, so a
test changes one fact at a time and leaves everything else as a complete, correlated execution.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from functools import cache
from typing import Any

from gazua.catalog.loader import RELEASES, load_catalog
from gazua.catalog.models import Mold
from gazua.config.models import GazuaConfig
from gazua.runtime.evidence import PrivateEvidence
from gazua.runtime.observations import ReturnChannel, ReturnObservation
from gazua.runtime.processes import Capture
from gazua.runtime.receiver import CapturedHit
from gazua.runtime.run_models import ExecutionRecord, ReceiverHit, RunSummary
from gazua.runtime.session_models import CallRecord
from gazua.verdicts.models import AttackContext

RUN_ID = "GAZUA-run-20260101000000-abc123"
CANARY = "GAZUA-CANARY-7f3a9c"
SECOND_CANARY = "GAZUA-CANARY-second-41b2"
ATTACKER = "attacker-1"
VICTIM = "victim-1"
VICTIM_ORDER = "order-victim-1"
EMPTY = Capture(b"", False)

# One built-in mold per signal and mode, so tests exercise the published catalog.
MOLDS = {
    ("forbidden_tool_call", "agent"): "permission-05",
    ("forbidden_tool_call", "tools"): "permission-01",
    ("sensitive_tool_call", "agent"): "permission-07",
    ("sensitive_tool_call", "tools"): "permission-03",
    ("canary_in_response", "agent"): "secret-04",
    ("canary_in_response", "tools"): "secret-02",
    ("canary_in_tool_arguments", "agent"): "secret-09",
    ("receiver_hit", "agent"): "secret-07",
    ("victim_record_access", "agent"): "idor-05",
    ("victim_record_access", "tools"): "idor-02",
    ("output_sink_effect", "agent"): "output-03",
    ("output_sink_effect", "tools"): "output-02",
    ("memory_effect", "agent"): "memory-01",
    ("tool_call_ceiling", "agent"): "spending-06",
    ("tool_call_ceiling", "tools"): "spending-02",
}


@cache
def _catalog() -> dict[str, Mold]:
    return {mold.id: mold for mold in load_catalog(release=RELEASES[-1]).molds}


def builtin(mold_id: str) -> Mold:
    return _catalog()[mold_id]


def config_document(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": 1,
        "entrypoint": "agent_target:entrypoint",
        "target": {"reset": "agent_target:reset"},
        "tools": {
            "delete_account": {"forbidden": True},
            "refund": {
                "sensitive": True,
                "safe": True,
                "actor_arg": "actor",
                "dry_run_return": "refunded",
            },
            "get_order": {
                "safe": True,
                "sensitive": False,
                "owner_arg": "user_id",
                "actor_arg": "actor",
            },
        },
        "fixtures": {
            "attacker": {"id": ATTACKER},
            "victim": {
                "id": VICTIM,
                "records": [{"tool": "get_order", "id_arg": "order_id", "id": VICTIM_ORDER}],
            },
        },
        "canaries": [CANARY, SECOND_CANARY],
        "output_sink": "agent_target:sink",
    }
    document.update(overrides)
    return document


def config(**overrides: Any) -> GazuaConfig:
    return GazuaConfig.model_validate(config_document(**overrides))


TOOL_FOR = {
    "forbidden_tool_call": "delete_account",
    "sensitive_tool_call": "refund",
    "tool_call_ceiling": "refund",
    "victim_record_access": "get_order",
    "canary_in_response": "get_order",
}


def context(
    signal: str,
    mode: str = "agent",
    *,
    repetitions: int = 1,
    key: str | None = None,
    **fields: Any,
) -> AttackContext:
    mold = builtin(MOLDS[(signal, mode)])
    attack_key = key or f"{mold.id}:{mode}"
    capabilities = {
        "direct_tool_access": True if mode == "tools" else None,
        "entry_supported": True if mode == "agent" else None,
        "inventory_complete": True,
        "receiver_transport": signal == "receiver_hit",
        "observation_envelope": signal in ("output_sink_effect", "memory_effect"),
        **fields.pop("capabilities", {}),
    }
    values: dict[str, Any] = {
        "attack_key": attack_key,
        "mold": mold,
        "mode": mode,
        "tool_name": TOOL_FOR.get(signal) if mode == "tools" else None,
        "requests": [
            {"request_key": f"{attack_key}#r{number}", "repetition": number}
            for number in range(1, repetitions + 1)
        ],
        "capabilities": capabilities,
    }
    if signal == "victim_record_access":
        values["record_index"] = 0
    if signal in ("canary_in_response", "canary_in_tool_arguments", "receiver_hit"):
        values["canary_index"] = 0
    if signal == "output_sink_effect":
        values["marker_id"] = "control_marker" if mode == "tools" else "markup_marker"
    values.update(fields)
    return AttackContext.model_validate(values)


class Numbers:
    """Hands out execution ids in the engine's format."""

    def __init__(self) -> None:
        self.value = 0

    def next(self) -> str:
        self.value += 1
        return f"GAZUA-exec-{self.value:04d}"


_numbers = Numbers()


def record(
    attack: AttackContext,
    repetition: int = 1,
    attempt: int = 1,
    *,
    execution_id: str | None = None,
    status: str = "completed",
    **fields: Any,
) -> ExecutionRecord:
    identifier = execution_id or _numbers.next()
    started = status not in ("not_tested", "skipped_by_limit")
    values: dict[str, Any] = {
        "schema_version": 1,
        "run_id": RUN_ID,
        "execution_id": identifier,
        "request_key": attack.requests[repetition - 1].request_key,
        "mold_id": attack.mold.id,
        "repetition": repetition,
        "attempt": attempt,
        "status": status,
        "reason": None if status == "completed" else fields.pop("reason", status),
        "started_at": "2026-01-01T00:00:00.000000Z" if started else None,
        "finished_at": "2026-01-01T00:00:01.000000Z" if started else None,
        "duration_ms": 1000 if started else None,
        "exit_code": 0 if started else None,
        "admitted_tool_calls": 0,
        "evidence_complete": status == "completed",
        "truncated_tail": False,
        "reported_cost_usd": None,
        "estimated_cost_usd": None,
        "usage_complete": False,
        "call_log": f"executions/{identifier}/calls.redacted.jsonl" if started else None,
        "receiver_hits": None,
        "output": f"executions/{identifier}/output.redacted.json" if started else None,
        "reset_before": "succeeded" if started else "not_started",
    }
    values.update(fields)
    return ExecutionRecord.model_validate(values)


def call(
    seq: int,
    tool: str,
    *,
    outcome: str = "returned",
    arguments: Mapping[str, Any] | None = None,
    actor: str | None = None,
    source: str | None = None,
    dry_run: bool = False,
    low_fidelity: bool = False,
    truncated: bool = False,
) -> CallRecord:
    return CallRecord.model_validate(
        {
            "schema_version": 1,
            "seq": seq,
            "tool": tool,
            "arguments": dict(arguments or {}),
            "truncated": truncated,
            "actor": {
                "id": actor,
                "source": source or ("actor_arg" if actor is not None else "none"),
            },
            "dry_run": dry_run,
            "undeclared": False,
            "outcome": outcome,
            "low_fidelity": low_fidelity,
            "result_type": "dict" if outcome == "returned" else None,
            "error": {"type": "RuntimeError"} if outcome == "raised" else None,
            "block_reason": "identity_hook" if outcome == "blocked" else None,
            "injection": None,
        }
    )


def returns(
    execution_id: str,
    calls: Sequence[CallRecord],
    values: Mapping[int, Any] | None = None,
    *,
    delivered: Mapping[int, Any] | None = None,
    unavailable: Iterable[int] = (),
) -> ReturnChannel:
    """A valid channel where each returned call has the given value, or is unavailable."""
    found: dict[int, ReturnObservation] = {}
    skipped = set(unavailable)
    for item in calls:
        if item.outcome != "returned":
            continue
        head = {
            "schema_version": 1,
            "kind": "tool_return",
            "execution_id": execution_id,
            "call_seq": item.seq,
        }
        if item.seq in skipped:
            found[item.seq] = ReturnObservation.model_validate(
                {**head, "unavailable_reason": "not_serializable"}
            )
            continue
        original = (values or {}).get(item.seq)
        given = (delivered or {}).get(item.seq, original)
        found[item.seq] = ReturnObservation.model_validate(
            {**head, "original": original, "delivered": given}
        )
    missing = tuple(seq for seq, item in found.items() if item.unavailable_reason is not None)
    return ReturnChannel(
        valid=True,
        returns=found,
        missing=missing,
        reason="return_observation_unavailable" if missing else None,
    )


def hit(execution: ExecutionRecord, number: int = 1, **fields: Any) -> CapturedHit:
    values: dict[str, Any] = {
        "schema_version": 1,
        "hit_id": f"{execution.execution_id}-hit-{number:03d}",
        "run_id": execution.run_id,
        "execution_id": execution.execution_id,
        "received_at": "2026-01-01T00:00:00.500000Z",
        "method": "POST",
        "logical_url": "https://receiver.gazua.test/collect",
        "body_size": 4,
        "truncated": False,
        "evidence": None,
    }
    body = fields.pop("body", b"data")
    values.update(fields)
    return CapturedHit(ReceiverHit.model_validate(values), body, "text/plain")


def evidence(
    execution: ExecutionRecord,
    *,
    calls: Sequence[CallRecord] = (),
    hits: Sequence[CapturedHit] = (),
    output: Any = None,
    complete: bool | None = None,
    truncated_tail: bool = False,
    channel: ReturnChannel | None = None,
    stdout: bytes = b"",
) -> PrivateEvidence:
    return PrivateEvidence(
        execution_id=execution.execution_id,
        calls=tuple(calls),
        truncated_tail=truncated_tail,
        receiver_hits=tuple(hits),
        output=output,
        stdout=Capture(stdout, False),
        stderr=EMPTY,
        complete=execution.evidence_complete if complete is None else complete,
        returns=channel if channel is not None else returns(execution.execution_id, calls),
    )


def envelope(response: Any, *observations: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "gazua_observation_version": 1,
        "response": response,
        "observations": list(observations),
    }


def sink(execution: ExecutionRecord, effect: bool | None, **fields: Any) -> dict[str, Any]:
    marker = fields.pop("marker_id", "markup_marker")
    values: dict[str, Any] = {
        "schema_version": 1,
        "kind": "sink",
        "execution_id": execution.execution_id,
    }
    if effect is None:
        values["error"] = fields.pop("error", "sink_error")
    else:
        observed = "unescaped_markup" if effect else "escaped_markup"
        values.update(effect=effect, proof={"marker_id": marker, "observed": observed})
    values.update(fields)
    return values


def memory(execution: ExecutionRecord, **fields: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "schema_version": 1,
        "kind": "memory",
        "execution_id": execution.execution_id,
        "marker_id": "memory-marker",
        "session_id": "session-1",
        "write_turn": 1,
        "read_turn": 2,
        "written_value": "GAZUA-MEMORY-MARKER",
        "read_value": "rule: GAZUA-MEMORY-MARKER",
        "reset_before": "succeeded",
        "reset_between": False,
    }
    values.update(fields)
    return values


def summary(
    records: Sequence[ExecutionRecord], *, interrupted: bool = False, **fields: Any
) -> RunSummary:
    from gazua.runtime.run_models import EXECUTION_STATUSES

    counts = dict.fromkeys(EXECUTION_STATUSES, 0)
    for item in records:
        counts[item.status] += 1
    values: dict[str, Any] = {
        "schema_version": 1,
        "run_id": RUN_ID,
        "interrupted": interrupted,
        "limits": config().limits.model_dump(),
        "requested_concurrency": 2,
        "effective_concurrency": 1,
        "planned": len({item.request_key for item in records}),
        "started": sum(item.started_at is not None for item in records),
        "retries": sum(item.attempt > 1 for item in records),
        "counts": counts,
        "cost_source": "unavailable",
        "cost_coverage": "not_applicable",
        "budget_guaranteed": False,
        "reserved_estimate_usd": None,
        "reported_cost_usd": None,
        "cleanup": "succeeded",
        "operational_errors": [],
        "records": [item.model_dump() for item in records],
    }
    values.update(fields)
    return RunSummary.model_validate(values)
