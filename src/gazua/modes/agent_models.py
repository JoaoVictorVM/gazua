"""Contracts of agent mode: options, preview, legitimate use and the mode's result.

Attack results stay the verdict engine's; legitimate tasks are measured apart, with their own
counts, and never become attack results. Everything here is plain data that crosses process and
report boundaries as JSON, without objects of the target or of a model provider.
"""

from __future__ import annotations

import math
from typing import Annotated, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, model_validator

from gazua.config.models import ToolName
from gazua.modes.tools_models import ToolsInventory
from gazua.runtime.run_models import CostSource, GazuaId, LimitOverrides, NonEmptyText, RunSummary
from gazua.verdicts.models import AttackContext, VerdictSummary

DEFAULT_REPETITIONS = 5
QUICK_REPETITIONS = 1
QUICK_MOLDS = 15
LEGITIMATE_PREFIX = "legitimate:"
LEGITIMATE_MOLD_PREFIX = "@legitimate:"
NOT_TESTED_TEXT = "Legitimate use: not tested"
NOT_REPORTED_TEXT = "Legitimate use: not reported"

ExitCode: TypeAlias = Literal[0, 1, 2]
TaskState: TypeAlias = Literal["succeeded", "failed", "not_tested"]
LegitimateCoverage: TypeAlias = Literal["complete", "partial", "not_tested"]
Code = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$")]
Count = Annotated[int, Field(ge=0)]
_RATE_TOLERANCE = 1e-9


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


def legitimate_request_key(index: int) -> str:
    return f"{LEGITIMATE_PREFIX}{index}"


def legitimate_mold_id(index: int) -> str:
    """A technical id that no catalog mold can have, used only in execution records."""
    return f"{LEGITIMATE_MOLD_PREFIX}{index}"


class AgentOptions(_Strict):
    """What the user chose for one agent run. Limits go to the engine unchanged.

    ``repetitions`` is for programmatic consumers; the command line has no flag for it.
    """

    mold: NonEmptyText | None = None
    quick: bool = False
    language: Literal["en", "pt"] = "en"
    overrides: LimitOverrides = Field(default_factory=LimitOverrides)
    config_path: NonEmptyText = "gazua.yaml"
    repetitions: Annotated[int, Field(ge=1, le=100)] | None = None

    @property
    def effective_repetitions(self) -> int:
        if self.repetitions is not None:
            return self.repetitions
        return QUICK_REPETITIONS if self.quick else DEFAULT_REPETITIONS


class AgentDiagnostic(_Strict):
    """Something the planning or the run found, as a code. It never quotes the target."""

    code: Code
    attack_key: NonEmptyText | None = None
    mold_id: NonEmptyText | None = None
    tool_name: NonEmptyText | None = None


class SelectedMold(_Strict):
    """One mold of the selection and how many of its scenarios can run."""

    mold_id: NonEmptyText
    scenarios: Count
    executable: Count
    impediments: list[Code] = Field(default_factory=list[str])


class AgentSelection(_Strict):
    """Which molds were chosen and why, before anything runs."""

    quick: bool
    exact_mold: NonEmptyText | None = None
    repetitions: Annotated[int, Field(ge=1)]
    molds: list[SelectedMold]


class AgentPreview(_Strict):
    """What the run shows before the first call to the agent.

    Molds, scenarios, repetitions and legitimate tasks are distinct counts: quick limits molds,
    not executions. Impeded slots spend no budget and stay in the result as not tested.
    """

    selection: AgentSelection
    inventory: ToolsInventory
    scenarios: Count
    executable_scenarios: Count
    attack_slots: Count
    impeded_slots: Count
    legitimate_tasks: Count
    planned_executions: Count
    max_runs: Annotated[int, Field(ge=1)]
    max_retries: Count
    requested_concurrency: Annotated[int, Field(ge=1)]
    effective_concurrency: Annotated[int, Field(ge=1)]
    cost_source: CostSource
    max_cost: float | None = None
    cost_per_run: float | None = None

    @property
    def molds(self) -> int:
        return len(self.selection.molds)


class LegitimateTask(_Strict):
    """The outcome of one declared legitimate task, with a pointer to its evidence.

    ``succeeded`` needs a finished call of the expected tool in the call log; ``dry_run`` says
    whether that call ran in dry-run. The request text is not repeated here.
    """

    task_index: Count
    request_key: NonEmptyText
    expected_tool: ToolName
    state: TaskState
    reason: Code | None
    execution_id: GazuaId | None
    call_seq: Annotated[int, Field(ge=1)] | None
    dry_run: bool | None

    @model_validator(mode="after")
    def _consistent(self) -> LegitimateTask:
        if self.state == "succeeded":
            if self.execution_id is None or self.call_seq is None or self.dry_run is None:
                raise ValueError("A succeeded task points to the call that proves it.")
            if self.reason is not None:
                raise ValueError("A succeeded task has no reason.")
        elif self.reason is None:
            raise ValueError("A failed or not tested task needs a reason.")
        elif self.call_seq is not None or self.dry_run is not None:
            raise ValueError("Only a succeeded task points to a call.")
        return self


class LegitimateUse(_Strict):
    """How many declared legitimate tasks used their expected tool.

    The rate is ``succeeded / evaluated`` over tasks that ran to a conclusion; tasks whose
    attempt never ended normally are not tested and stay out of the denominator.
    """

    model_config = ConfigDict(title="Gazua legitimate use")

    planned: Count
    evaluated: Count
    succeeded: Count
    failed: Count
    not_tested: Count
    rate: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)] | None
    coverage: LegitimateCoverage
    tasks: list[LegitimateTask]

    @model_validator(mode="after")
    def _consistent(self) -> LegitimateUse:
        states = [task.state for task in self.tasks]
        problems = [
            self.planned != len(self.tasks),
            self.succeeded != states.count("succeeded"),
            self.failed != states.count("failed"),
            self.not_tested != states.count("not_tested"),
            self.evaluated != self.succeeded + self.failed,
            self.planned != self.evaluated + self.not_tested,
            self.coverage != legitimate_coverage(self.planned, self.evaluated, self.not_tested),
            len({task.task_index for task in self.tasks}) != len(self.tasks),
            len({task.request_key for task in self.tasks}) != len(self.tasks),
        ]
        if any(problems):
            raise ValueError("The legitimate use counts, coverage and tasks disagree.")
        if self.evaluated == 0:
            if self.rate is not None:
                raise ValueError("Without evaluated tasks there is no rate.")
        elif self.rate is None or not math.isclose(
            self.rate, self.succeeded / self.evaluated, abs_tol=_RATE_TOLERANCE
        ):
            raise ValueError("The rate is succeeded over evaluated tasks.")
        return self

    @property
    def text(self) -> str:
        """The fixed sentence that terminal, Markdown and HTML show."""
        if self.planned == 0 or self.evaluated == 0:
            if self.planned == 0:
                return NOT_TESTED_TEXT
            return f"{NOT_TESTED_TEXT} ({self.planned} declared, none evaluated)"
        percent = round(100 * (self.rate or 0.0))
        text = (
            f"Legitimate use: {self.succeeded}/{self.evaluated} tasks used the expected tool "
            f"({percent}%)"
        )
        if self.not_tested:
            text += f", {self.not_tested} not tested"
        return f"{text}. Coverage: {self.coverage}."


def legitimate_coverage(planned: int, evaluated: int, not_tested: int) -> LegitimateCoverage:
    if evaluated == 0:
        return "not_tested"
    return "partial" if not_tested else "complete"


def empty_legitimate_use() -> LegitimateUse:
    return LegitimateUse(
        planned=0,
        evaluated=0,
        succeeded=0,
        failed=0,
        not_tested=0,
        rate=None,
        coverage="not_tested",
        tasks=[],
    )


class AgentResult(_Strict):
    """The result of one agent run, for the CLI and for later consumers.

    ``engine`` holds every execution, legitimate tasks included; ``verdicts`` holds attacks
    only, judged by the verdict engine with its own statistics and gate. ``legitimate_use`` is
    measured apart and never changes the security gate.
    """

    mode: Literal["agent"] = "agent"
    run_id: GazuaId
    inventory: ToolsInventory
    selection: AgentSelection
    contexts: list[AttackContext]
    engine: RunSummary
    verdicts: VerdictSummary
    legitimate_use: LegitimateUse
    executed: bool
    diagnostics: list[AgentDiagnostic] = Field(default_factory=list[AgentDiagnostic])
    reproduction: dict[str, list[NonEmptyText]] = Field(default_factory=dict[str, list[str]])
    exit_code: ExitCode

    @property
    def result_order(self) -> list[str]:
        return [context.attack_key for context in self.contexts]

    @property
    def has_gated_findings(self) -> bool:
        return self.verdicts.has_gated_findings
