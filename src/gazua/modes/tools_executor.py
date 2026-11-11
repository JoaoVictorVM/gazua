"""Executor of tools mode, run by the engine inside each supervised worker.

It imports the test module, reconciles the tools again and binds the mold again from validated
data; identity and arguments never come from the request as free values. Calls go only through
the released proxies. The tool's return is not copied into the output: the wrapper's private
capture is the evidence, and the verdict engine reads it before it is deleted.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

from gazua.catalog.bindings import OUTPUT_MARKERS, BindingContext, BindingImpediment, bind_mold
from gazua.catalog.models import Mold
from gazua.config.references import resolve_reference
from gazua.integration.errors import GazuaBlockedError
from gazua.integration.limits import CEILING_REASON
from gazua.modes.tools_models import ToolsInventory
from gazua.modes.tools_plan import check_arguments, needs_attacker
from gazua.runtime.observations import observe_sink, output_envelope
from gazua.runtime.session_models import SessionDocumentV2
from gazua.runtime.tools import InvocationRefused, ToolInventory
from gazua.runtime.worker import ExecutionContext

NEUTRAL_RESPONSE: Final = "tools_mode_call_finished"


def _index(value: object) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value < 0:
        raise InvocationRefused("request_invalid")
    return value


def execute(request: Mapping[str, Any], context: ExecutionContext) -> dict[str, Any]:
    """Runs one tools attack unit and returns the observation envelope as the output."""
    payload: Mapping[str, Any] = request["payload"]
    mold = Mold.model_validate(payload["mold"])
    action = mold.tools_action
    if mold.id != request["mold_id"] or action is None:
        raise InvocationRefused("request_invalid")
    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str):
        raise InvocationRefused("request_invalid")
    record_index = _index(payload.get("record_index"))
    canary_index = _index(payload.get("canary_index"))
    language = payload.get("language", "en")
    if language not in ("en", "pt"):
        raise InvocationRefused("request_invalid")
    attacker = needs_attacker(action)
    if (request.get("actor") == "attacker") != attacker:
        raise InvocationRefused("request_invalid")
    binding = BindingContext.from_config(
        context.config,
        tool_name,
        record_index=record_index or 0,
        canary_index=canary_index or 0,
    )
    bound = bind_mold(mold, binding, mode="tools", language=language)
    if isinstance(bound, BindingImpediment):
        raise InvocationRefused("binding_changed")
    if action.kind == "probe_output_sink":
        marker = OUTPUT_MARKERS[action.variant]
        observed = observe_sink(context, marker, marker_id=action.variant)
        return {"output": output_envelope(marker, [observed] if observed is not None else [])}
    if context.entrypoint is None:
        raise InvocationRefused("entrypoint_missing")
    # Importing the module registers its tools; the entrypoint itself is never called.
    resolve_reference(context.entrypoint, "entrypoint")
    tools = ToolInventory.collect(context.config)
    described = ToolsInventory.model_validate(tools.describe()).get(tool_name)
    if described is None or not described.runnable or not described.signature_available:
        raise InvocationRefused("inventory_changed")
    missing, refused = check_arguments(described, bound, context.config)
    if missing or refused:
        raise InvocationRefused("inventory_changed")
    session = SessionDocumentV2.model_validate_json(
        context.session_path.read_text(encoding="utf-8")
    )
    for _ in range(bound.calls):
        try:
            if attacker:
                tools.invoke_as(
                    tool_name,
                    "attacker",
                    bound.arguments,
                    session=session,
                    directory=context.directory,
                )
            else:
                tools.invoke_without_actor(
                    tool_name, bound.arguments, session=session, directory=context.directory
                )
        except InvocationRefused:
            raise
        except GazuaBlockedError as blocked:
            if blocked.reason == CEILING_REASON:
                break
            raise
        # The proxy already recorded the call as raised. An exception from the target is not
        # a proven refusal, and the verdict engine decides what it means from that record.
        except Exception:  # noqa: BLE001
            break
    return {"output": output_envelope(NEUTRAL_RESPONSE)}
