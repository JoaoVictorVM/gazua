"""Run documents with every verdict state, built from the verdict engine's own results.

The scenarios cover a proven IDOR, a resisted one, a not tested and a not applicable call, and
an unhandled output that stays a conditional risk. Tests change the evidence or the treatment
and read the document the same way reports do.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from verdict_factory import (
    ATTACKER,
    RUN_ID,
    VICTIM,
    VICTIM_ORDER,
    call,
    config,
    context,
    envelope,
    evidence,
    record,
    returns,
    summary,
)

from gazua.config.models import GazuaConfig
from gazua.reports.builder import ExcerptSource, PlainTreatment, Treatment, build_run_document
from gazua.reports.models import RunDocument
from gazua.runtime.evidence import PrivateEvidence
from gazua.runtime.run_models import ExecutionRecord
from gazua.verdicts.engine import VerdictCollector
from gazua.verdicts.models import AttackContext

CREATED_AT = "2026-01-01T00:00:00.000000Z"
TARGET = "tools_target:entrypoint"
FOUND = "tools:idor-02:proven"
RESISTED = "tools:idor-02:resisted"
NOT_TESTED = "tools:permission-03:waiting"
NOT_APPLICABLE = "tools:permission-01:absent"
CONDITIONAL = "agent:output-03:unverified"


def victim_order(**extra: Any) -> dict[str, Any]:
    return {"order_id": VICTIM_ORDER, "user_id": VICTIM, **extra}


@dataclass
class Scenarios:
    configuration: GazuaConfig
    contexts: list[AttackContext]
    pairs: list[tuple[ExecutionRecord, PrivateEvidence | None]]

    def records(self) -> list[ExecutionRecord]:
        return [item for item, _ in self.pairs]


def five_states(
    *, found_return: Any = None, extra_found: Sequence[AttackContext] = ()
) -> Scenarios:
    configuration = config(output_sink=None)
    proven = context("victim_record_access", "tools", key=FOUND)
    resisted = context("victim_record_access", "tools", key=RESISTED)
    waiting = context("sensitive_tool_call", "tools", key=NOT_TESTED)
    absent = context(
        "forbidden_tool_call",
        "tools",
        key=NOT_APPLICABLE,
        impediment={"reason": "no_applicable_tool"},
    )
    unverified = context("output_sink_effect", "agent", key=CONDITIONAL)
    pairs: list[tuple[ExecutionRecord, PrivateEvidence | None]] = []
    for item, value in ((proven, found_return or victim_order()), (resisted, None)):
        execution = record(item)
        calls = [call(1, "get_order", arguments={"order_id": VICTIM_ORDER}, actor=ATTACKER)]
        channel = returns(execution.execution_id, calls, {1: value})
        pairs.append((execution, evidence(execution, calls=calls, channel=channel)))
    for item in extra_found:
        execution = record(item)
        calls = [call(1, "get_order", arguments={"order_id": VICTIM_ORDER}, actor=ATTACKER)]
        channel = returns(execution.execution_id, calls, {1: victim_order()})
        pairs.append((execution, evidence(execution, calls=calls, channel=channel)))
    pairs.append((record(waiting, status="not_tested", reason="receiver_unavailable"), None))
    unhandled = record(unverified)
    pairs.append((unhandled, evidence(unhandled, output=envelope("<b>hi</b>"))))
    contexts = [proven, resisted, waiting, absent, unverified, *extra_found]
    return Scenarios(configuration, contexts, pairs)


def document(
    scenarios: Scenarios | None = None,
    *,
    treatment: Treatment | None = None,
    target: str = TARGET,
    on_evidence: Callable[[ExecutionRecord, PrivateEvidence], None] | None = None,
    excerpts: ExcerptSource | None = None,
    exit_code: int = 1,
    language: str = "en",
) -> RunDocument:
    chosen = scenarios or five_states()
    collector = VerdictCollector(chosen.contexts, chosen.configuration)
    for execution, private in chosen.pairs:
        if private is not None:
            collector(execution, private)
            if on_evidence is not None:
                on_evidence(execution, private)
    engine = summary(chosen.records())
    verdicts = collector.finalize(engine)
    return build_run_document(
        run_id=RUN_ID,
        created_at=CREATED_AT,
        target_ref=target,
        mode="tools",
        language=language,  # type: ignore[arg-type]
        engine=engine,
        verdicts=verdicts,
        contexts=chosen.contexts,
        reproduction={
            item.attack_key: [
                "gazua",
                "run",
                "--tools",
                "--config",
                "gazua.yaml",
                "--mold",
                item.mold.id,
            ]
            for item in chosen.contexts
        },
        treatment=treatment or PlainTreatment(),
        exit_code=exit_code,  # type: ignore[arg-type]
        config=chosen.configuration,
        excerpts=excerpts,
        gazua_version="0.1.0",
    )
