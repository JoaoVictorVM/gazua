"""Gazua side of the tool contract: sessions, tool inventory, hooks and the call log.

Run engines, verdicts and tools mode use these. Nothing here runs at ``import gazua``.
"""

from gazua.runtime.call_log import CallLogReading, read_call_log
from gazua.runtime.hooks import HookError, RateLimited, ResetFailed, call_entrypoint, call_reset
from gazua.runtime.session_models import (
    AnySession,
    CallRecord,
    SessionActor,
    SessionDocument,
    SessionDocumentV2,
    SessionInjection,
    SessionReceiver,
    SessionTool,
)
from gazua.runtime.session_writer import (
    SessionExecution,
    SessionFile,
    activate,
    build_session,
    write_session,
)
from gazua.runtime.tools import (
    InventoryEntry,
    InvocationRefused,
    NotSafeToCall,
    ToolInventory,
    ToolSummary,
    check_fidelity,
)

__all__ = [
    "AnySession",
    "CallLogReading",
    "CallRecord",
    "HookError",
    "InventoryEntry",
    "InvocationRefused",
    "NotSafeToCall",
    "RateLimited",
    "ResetFailed",
    "SessionActor",
    "SessionDocument",
    "SessionDocumentV2",
    "SessionExecution",
    "SessionFile",
    "SessionInjection",
    "SessionReceiver",
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
