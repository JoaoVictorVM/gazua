"""Executor of agent mode, run by the engine inside each supervised worker.

It binds the mold again from validated configuration, sends the turns to the project's
entrypoint and reports the response in an observation envelope. Direct attacks send each turn
as a user message. Indirect attacks send the declared trigger message and arm one injection at
a time, so each turn reaches only the declared tool's text result that follows it. All turns of
one attempt share this worker and its session, with no reset between them.

The entrypoint uses the project's own model and credential; nothing here reads either.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import JsonValue

from gazua.catalog.bindings import BindingContext, BindingImpediment, bind_mold
from gazua.catalog.models import Mold
from gazua.catalog.selection import INDIRECT_ENTRIES
from gazua.config.models import GazuaConfig
from gazua.integration.injection import armed_turn
from gazua.runtime.hooks import call_entrypoint
from gazua.runtime.observations import observe_sink, output_envelope
from gazua.runtime.session_models import SessionDocumentV2, turn_injection_id
from gazua.runtime.tools import InvocationRefused
from gazua.runtime.worker import ExecutionContext

SINK_MARKER = "markup_marker"


def _index(value: object) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value < 0:
        raise InvocationRefused("request_invalid")
    return value


def _legitimate(
    request: Mapping[str, Any], payload: Mapping[str, Any], context: ExecutionContext
) -> dict[str, Any]:
    config: GazuaConfig = context.config
    index = _index(payload.get("task_index"))
    if index is None or index >= len(config.legit_tasks) or request.get("injections"):
        raise InvocationRefused("request_invalid")
    task = config.legit_tasks[index]
    if payload.get("request") != task.request or payload.get("expected_tool") != task.expected_tool:
        raise InvocationRefused("binding_changed")
    if request.get("actor") is not None or context.entrypoint is None:
        raise InvocationRefused("request_invalid")
    response = call_entrypoint(context.entrypoint, task.request)
    return {"output": output_envelope(response)}


def _turn_ids(context: ExecutionContext, request_key: str, tool: str, turns: int) -> list[str]:
    """The injection ids of this attempt, checked against the session the engine wrote."""
    session = SessionDocumentV2.model_validate_json(
        context.session_path.read_text(encoding="utf-8")
    )
    expected = [turn_injection_id(request_key, turn) for turn in range(1, turns + 1)]
    found = [item.id for item in session.injections if item.tool == tool]
    if found != expected or any(item.max_deliveries != 1 for item in session.injections):
        raise InvocationRefused("binding_changed")
    return expected


def _attack(
    request: Mapping[str, Any], payload: Mapping[str, Any], context: ExecutionContext
) -> dict[str, Any]:
    config: GazuaConfig = context.config
    mold = Mold.model_validate(payload["mold"])
    if mold.id != request["mold_id"] or mold.agent_action is None:
        raise InvocationRefused("request_invalid")
    language = payload.get("language", "en")
    if language not in ("en", "pt"):
        raise InvocationRefused("request_invalid")
    tool_name = payload.get("tool_name")
    if tool_name is not None and not isinstance(tool_name, str):
        raise InvocationRefused("request_invalid")
    binding = BindingContext.from_config(
        config,
        tool_name,
        record_index=_index(payload.get("record_index")) or 0,
        canary_index=_index(payload.get("canary_index")) or 0,
    )
    bound = bind_mold(mold, binding, mode="agent", language=language)
    if isinstance(bound, BindingImpediment) or len(bound.turns) != payload.get("turns"):
        raise InvocationRefused("binding_changed")
    if context.entrypoint is None:
        raise InvocationRefused("entrypoint_missing")
    responses: list[str] = []
    if mold.entry == "user_message":
        if request.get("injections"):
            raise InvocationRefused("request_invalid")
        responses.extend(call_entrypoint(context.entrypoint, turn) for turn in bound.turns)
    elif mold.entry in INDIRECT_ENTRIES:
        declared = config.agent_entries.get(mold.entry)
        if declared is None:
            raise InvocationRefused("entry_unavailable")
        for injection_id in _turn_ids(context, request["key"], declared.tool, len(bound.turns)):
            # Only this turn can be delivered while the trigger message runs.
            with armed_turn(injection_id):
                responses.append(call_entrypoint(context.entrypoint, declared.request))
    else:
        raise InvocationRefused("entry_unavailable")
    response: JsonValue = responses[0] if len(responses) == 1 else list(responses)
    observations: list[dict[str, Any]] = []
    if mold.success.signal == "output_sink_effect":
        observed = observe_sink(context, response, marker_id=SINK_MARKER)
        if observed is not None:
            observations.append(observed)
    return {"output": output_envelope(response, observations)}


def execute(request: Mapping[str, Any], context: ExecutionContext) -> dict[str, Any]:
    """Runs one agent attack or legitimate task and returns the observation envelope."""
    payload: Mapping[str, Any] = request["payload"]
    kind = payload.get("kind")
    if kind == "legitimate":
        return _legitimate(request, payload, context)
    if kind == "attack":
        return _attack(request, payload, context)
    raise InvocationRefused("request_invalid")
