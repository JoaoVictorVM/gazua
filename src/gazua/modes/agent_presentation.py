"""Fixed sentences of agent mode: preview, stop reasons and legitimate use.

Every line comes from a template filled with counts, codes and validated names only. Nothing the
agent answered, and no request text, is interpolated.
"""

from __future__ import annotations

from typing import Final

from gazua.modes.agent_models import NOT_REPORTED_TEXT, LegitimateUse
from gazua.runtime.run_models import IDENTICAL_FAILURE_LIMIT, RunSummary

AUTHENTICATION_MESSAGE: Final = "The agent could not authenticate; Gazua does not manage its key"
AGENT_WARNING: Final = (
    "Agent mode sends attack text to your model provider through your agent and may cost "
    "money. It is meant for nightly and pre-release runs, not for every pull request."
)


def stop_message(summary: RunSummary) -> str | None:
    """Why the run stopped early, or None when no stop policy closed it."""
    reason, error = summary.stop_reason, summary.stop_error
    if reason is None:
        return None
    if reason == "agent_authentication_failed":
        return AUTHENTICATION_MESSAGE
    if reason == "persistent_rate_limit":
        return (
            "The agent kept reporting rate limits (429); the run stopped and the remaining "
            "executions are not tested."
        )
    shared = "unknown error"
    if error is not None:
        shared = error.code.replace("_", " ")
        if error.error_type is not None:
            shared += f" ({error.error_type})"
    return (
        f"The run stopped after {IDENTICAL_FAILURE_LIMIT} consecutive identical failures; the "
        f"remaining executions are not tested. Shared error: {shared}."
    )


def legitimate_text(measured: LegitimateUse | None) -> str:
    """``Legitimate use: not tested`` without tasks; a document without the field says so."""
    return NOT_REPORTED_TEXT if measured is None else measured.text


def legitimate_task_lines(measured: LegitimateUse | None) -> list[str]:
    if measured is None:
        return []
    lines: list[str] = []
    for task in measured.tasks:
        detail = task.state.replace("_", " ")
        if task.reason is not None:
            detail += f", {task.reason.replace('_', ' ')}"
        if task.dry_run:
            detail += ", call in dry-run"
        where = f" ({task.execution_id}, call {task.call_seq})" if task.call_seq else ""
        lines.append(f"  Task {task.task_index}, expects {task.expected_tool}: {detail}{where}")
    return lines
