"""A store whose order tool echoes a value planted in the test environment.

The value reaches the tool return, the worker's stdout and stderr, so a test can check that
no output of Gazua keeps it. Gazua itself never reads it: the target does, as an application
would leak its own configuration. A second tool can be registered under a hostile name.
"""

import os
import sys
from typing import Any

import gazua

CANARY = "GAZUA-CANARY-7f3a9c"
ECHO = "GAZUA_TEST_ECHO"
HOSTILE_NAME = "GAZUA_TEST_TOOL_NAME"


def get_order(order_id: str, user_id: str | None = None, actor: str | None = None) -> Any:
    value = os.environ.get(ECHO, "")
    print(f"echo {value}")
    sys.stderr.write(f"echo {value}\n")
    if order_id != "order-victim-1":
        return None
    return {"order_id": order_id, "user_id": "victim-1", "note": value, "canary": CANARY}


def unused(value: str = "x") -> str:
    return value


_tools: dict[str, Any] = {"get_order": get_order}
_hostile = os.environ.get(HOSTILE_NAME)
if _hostile:
    _tools[_hostile] = unused
TOOLS = gazua.wrap(_tools)


def entrypoint(message: str) -> str:
    raise RuntimeError("tools mode never calls the entrypoint")
