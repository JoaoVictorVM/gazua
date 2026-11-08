"""Gazua side of the tool contract and the run engine.

Sessions, tool inventory, hooks, the call log and the engine that runs each attempt in a
supervised process. Verdicts, run modes, verification and adapters build on these. Nothing
here runs at ``import gazua``.
"""

from gazua.runtime.call_log import CallLogReading, read_call_log
from gazua.runtime.engine import execute_plan, prepare_run
from gazua.runtime.evidence import PrivateEvidence
from gazua.runtime.hooks import HookError, RateLimited, ResetFailed, call_entrypoint, call_reset
from gazua.runtime.receiver import CapturedHit
from gazua.runtime.run_models import (
    COST_WARNING,
    BackoffStarted,
    BudgetWarning,
    CleanupFinished,
    ExecutionFinished,
    ExecutionRecord,
    ExecutionRequest,
    ExecutionStarted,
    ExecutionStatus,
    LimitOverrides,
    Progress,
    ReceiverHit,
    RunEvent,
    RunFinished,
    RunPlan,
    RunPrepared,
    RunSummary,
)
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
from gazua.runtime.worker import ExecutionContext

__all__ = [
    "COST_WARNING",
    "AnySession",
    "BackoffStarted",
    "BudgetWarning",
    "CallLogReading",
    "CallRecord",
    "CapturedHit",
    "CleanupFinished",
    "ExecutionContext",
    "ExecutionFinished",
    "ExecutionRecord",
    "ExecutionRequest",
    "ExecutionStarted",
    "ExecutionStatus",
    "HookError",
    "InventoryEntry",
    "InvocationRefused",
    "LimitOverrides",
    "NotSafeToCall",
    "PrivateEvidence",
    "Progress",
    "RateLimited",
    "ReceiverHit",
    "ResetFailed",
    "RunEvent",
    "RunFinished",
    "RunPlan",
    "RunPrepared",
    "RunSummary",
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
    "execute_plan",
    "prepare_run",
    "read_call_log",
    "write_session",
]
