"""TypeScript target adapter: a Node runner per attempt, driven by the supervised worker.

The npm package ``gazua`` wraps the agent's tools inside Node and writes the same session
evidence as the Python wrapper; this package starts its runner with a fixed argument vector,
speaks the local JSON Lines protocol and hands the responses to agent mode. Importing it only
loads the standard library and Pydantic models; Node starts only inside a supervised worker.
"""

from __future__ import annotations

from typing import Final

EXECUTOR: Final = "gazua.typescript.executor:execute"
DESCRIBE_EXECUTOR: Final = "gazua.typescript.executor:describe"

__all__ = ["DESCRIBE_EXECUTOR", "EXECUTOR"]
