"""A minimal real executor, as a mode would provide, for run engine tests."""

from collections.abc import Mapping
from typing import Any

from gazua.runtime import call_entrypoint
from gazua.runtime.worker import ExecutionContext


def execute(request: Mapping[str, Any], context: ExecutionContext) -> dict[str, Any]:
    assert context.entrypoint is not None
    payload = request["payload"]
    response = call_entrypoint(context.entrypoint, payload["message"])
    return {"output": response, "usage_complete": bool(payload.get("usage_complete", False))}
