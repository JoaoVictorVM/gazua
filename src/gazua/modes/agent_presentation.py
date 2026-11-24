"""Fixed sentences of agent mode: preview, stop reasons and legitimate use.

Every line comes from a template filled with counts, codes and validated names only. Nothing the
agent answered, and no request text, is interpolated.
"""

from __future__ import annotations

from typing import Final

from gazua.modes.agent_models import NOT_REPORTED_TEXT, AgentPreview, LegitimateUse
from gazua.reports.terminal import safe_line as sanitize
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


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" + ("" if count == 1 else "s")


def _cost_line(preview: AgentPreview) -> str:
    if preview.max_cost is None:
        return "Cost: no max_cost set; Gazua does not limit spending for this run."
    limit = f"{preview.max_cost:g} USD"
    if preview.cost_source == "estimated" and preview.cost_per_run is not None:
        return (
            f"Cost: limit {limit}, estimated at {preview.cost_per_run:g} USD per execution "
            "from cost_per_run."
        )
    if preview.cost_source == "reported":
        return (
            f"Cost: limit {limit}, applied only to the cost your agent reports with "
            "gazua.report_usage."
        )
    return f"Cost: limit {limit}, but no reported usage or cost_per_run; it cannot apply."


def preview_lines(preview: AgentPreview) -> list[str]:
    """What the run shows before the first call to the agent. Names are sanitized."""
    selection = preview.selection
    shape = _plural(preview.molds, "mold")
    if selection.quick:
        shape += " (quick: up to 15 molds, spread over the damages)"
    repetition = _plural(selection.repetitions, "repetition")
    lines = [
        f"Agent mode: {shape}, {_plural(preview.scenarios, 'scenario')} "
        f"({preview.executable_scenarios} can run), {repetition} each, "
        f"{_plural(preview.legitimate_tasks, 'legitimate task')}.",
        f"Planned: {_plural(preview.planned_executions, 'execution')} "
        f"({preview.attack_slots} attack, {preview.legitimate_tasks} legitimate). "
        f"Limit {preview.max_runs}. {preview.impeded_slots} impeded slots are not tested and "
        "use no budget.",
        f"Retries after a reported 429: up to {preview.max_retries} per execution, counted in "
        f"the limit of {preview.max_runs}.",
    ]
    concurrency = f"Concurrency {preview.effective_concurrency}"
    if preview.effective_concurrency < preview.requested_concurrency:
        concurrency += (
            f" (requested {preview.requested_concurrency}, target.reset runs one at a time)."
        )
    else:
        concurrency += "."
    lines.append(concurrency)
    lines.append(_cost_line(preview))
    if selection.quick or selection.exact_mold is not None:
        lines.append(
            "Selected molds: " + ", ".join(sanitize(item.mold_id) for item in selection.molds)
        )
    for item in selection.molds:
        if item.impediments:
            reasons = ", ".join(code.replace("_", " ") for code in item.impediments)
            lines.append(
                f"  {sanitize(item.mold_id)}: {item.executable} of "
                f"{_plural(item.scenarios, 'scenario')} can run; not tested: {reasons}."
            )
    if preview.http_origin is not None:
        lines.extend(http_lines(preview.http_origin, traces=bool(preview.traces)))
    else:
        runtime = preview.inventory.typescript
        if runtime is not None:
            lines.append(
                f"Target: TypeScript module in Node {sanitize(runtime.node_version)} "
                f"(npm gazua {sanitize(runtime.sdk_version)}); it runs with your permissions."
            )
        registered = [tool for tool in preview.inventory.tools if tool.registered]
        real = [sanitize(tool.name) for tool in registered if tool.runnable]
        dry = [sanitize(tool.name) for tool in registered if not tool.runnable]
        lines.append(
            f"Tools: real {', '.join(real) if real else 'none'}; "
            f"dry-run {', '.join(dry) if dry else 'none'}."
        )
    lines.append(f"Warning: {AGENT_WARNING}")
    return lines


HTTP_WARNING: Final = (
    "HTTP has no dry-run: every request goes to the authorized endpoint and its tools run for "
    "real there."
)


def http_lines(origin: str, *, traces: bool) -> list[str]:
    """The HTTP target and its tool visibility, in fixed sentences."""
    visibility = (
        "Traces: tool calls are proven only by OpenTelemetry spans received on the loopback."
        if traces
        else "Traces: off; attacks that need to see tool calls are not tested."
    )
    return [f"Target: POST to {sanitize(origin)}. {HTTP_WARNING}", visibility]
