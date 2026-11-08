"""Real executors, as the tools and agent modes would provide, for verdict engine tests."""

from collections.abc import Mapping
from typing import Any

from gazua.catalog.bindings import OUTPUT_MARKERS
from gazua.runtime import call_entrypoint
from gazua.runtime.observations import observe_sink, output_envelope
from gazua.runtime.worker import ExecutionContext


def agent(request: Mapping[str, Any], context: ExecutionContext) -> dict[str, Any]:
    """Sends one message to the agent; with ``envelope`` it reports observations too."""
    assert context.entrypoint is not None
    payload = request["payload"]
    response = call_entrypoint(context.entrypoint, payload["message"])
    if not payload.get("envelope"):
        return {"output": response}
    observations = []
    sink_case = payload.get("sink")
    if sink_case is not None:
        marker_id = payload.get("marker_id", "markup_marker")
        value = f"{sink_case}:{OUTPUT_MARKERS[marker_id]}"
        observed = observe_sink(context, value, marker_id=marker_id)
        if observed is not None:
            observations.append(observed)
    return {"output": output_envelope(response, observations)}


def tools(request: Mapping[str, Any], context: ExecutionContext) -> dict[str, Any]:
    """Calls one wrapped tool directly, as the attacker the session imposes.

    The return is not copied into the output: the wrapper's private capture is the evidence,
    and only the type persists.
    """
    import verdict_target

    payload = request["payload"]
    value = verdict_target.TOOLS[payload["tool"]](**payload.get("arguments", {}))
    return {"output": output_envelope(type(value).__name__)}
