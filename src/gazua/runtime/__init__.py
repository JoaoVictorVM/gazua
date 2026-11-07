"""Gazua side of the tool contract: sessions, tool inventory, hooks and the call log.

Run engines, verdicts and tools mode use these. Nothing here runs at ``import gazua``.
"""

from gazua.runtime.call_log import CallLogReading, read_call_log
from gazua.runtime.hooks import HookError, ResetFailed, call_entrypoint, call_reset
from gazua.runtime.session_models import (
    CallRecord,
    SessionActor,
    SessionDocument,
    SessionInjection,
    SessionTool,
)
from gazua.runtime.session_writer import SessionFile, activate, build_session, write_session
from gazua.runtime.tools import (
    InventoryEntry,
    InvocationRefused,
    NotSafeToCall,
    ToolInventory,
    ToolSummary,
    check_fidelity,
)

__all__ = [
    "CallLogReading",
    "CallRecord",
    "HookError",
    "InventoryEntry",
    "InvocationRefused",
    "NotSafeToCall",
    "ResetFailed",
    "SessionActor",
    "SessionDocument",
    "SessionFile",
    "SessionInjection",
    "SessionTool",
    "ToolInventory",
    "ToolSummary",
    "activate",
    "build_session",
    "call_entrypoint",
    "call_reset",
    "check_fidelity",
    "read_call_log",
    "write_session",
]
