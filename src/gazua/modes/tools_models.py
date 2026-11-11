"""Contracts of tools mode: the discovered tool inventory, the options and the mode's result.

The inventory describes the target's tools without holding any of their objects, so it crosses
the process boundary as JSON and the supervisor never imports the target. The result carries the
engine and verdict summaries as they are; it is not a report format.
"""

from __future__ import annotations

from typing import Annotated, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field

from gazua.runtime.run_models import LimitOverrides, NonEmptyText, RunSummary
from gazua.verdicts.models import AttackContext, VerdictSummary

ParameterKind: TypeAlias = Literal[
    "positional_only", "positional_or_keyword", "var_positional", "keyword_only", "var_keyword"
]
SkipReason: TypeAlias = Literal[
    "tool_not_found", "tool_name_conflict", "missing_safe", "tool_unclassified"
]
ExitCode: TypeAlias = Literal[0, 1, 2]
Code = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$")]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ParameterInfo(_Strict):
    """One parameter of a tool: its name, kind and whether it has a default, never the value."""

    name: NonEmptyText
    kind: ParameterKind
    has_default: bool


class DiscoveredTool(_Strict):
    """One tool name as the discovery saw it, declared, registered or both."""

    name: NonEmptyText
    registered: bool
    safe: bool
    classified: bool
    ambiguous: bool = False
    required_arguments: list[NonEmptyText] = Field(default_factory=list[str])
    parameters: list[ParameterInfo] = Field(default_factory=list[ParameterInfo])
    signature_available: bool
    supports_sync: bool
    supports_async: bool
    diagnostics: list[Code] = Field(default_factory=list[str])

    @property
    def skip_reason(self) -> SkipReason | None:
        """Why Gazua will not call this tool; None when it can run."""
        if not self.registered:
            return "tool_not_found"
        if self.ambiguous:
            return "tool_name_conflict"
        if not self.safe:
            return "missing_safe"
        if not self.classified:
            return "tool_unclassified"
        return None

    @property
    def runnable(self) -> bool:
        return self.skip_reason is None

    def accepts(self, argument: str) -> bool:
        """Whether a keyword argument fits the inspected signature."""
        for parameter in self.parameters:
            if parameter.name == argument:
                return parameter.kind in ("positional_or_keyword", "keyword_only")
        return any(parameter.kind == "var_keyword" for parameter in self.parameters)


class ToolsInventory(_Strict):
    """Every tool name seen by discovery, in name order.

    ``complete`` is true only after the test module was imported and reconciled in full; only a
    complete inventory can show that no tool fits a mold.
    """

    complete: bool
    tools: list[DiscoveredTool] = Field(default_factory=list[DiscoveredTool])

    def get(self, name: str) -> DiscoveredTool | None:
        return next((tool for tool in self.tools if tool.name == name), None)

    @property
    def runnable(self) -> list[DiscoveredTool]:
        return [tool for tool in self.tools if tool.runnable]

    @property
    def skipped(self) -> list[DiscoveredTool]:
        return [tool for tool in self.tools if not tool.runnable]


class ToolsOptions(_Strict):
    """What the user chose for one tools run. Limits go to the engine unchanged."""

    mold: NonEmptyText | None = None
    language: Literal["en", "pt"] = "en"
    overrides: LimitOverrides = Field(default_factory=LimitOverrides)
    config_path: NonEmptyText = "gazua.yaml"


class ToolsDiagnostic(_Strict):
    """Something the planning or the run found, as a code. It never quotes the target."""

    code: Code
    attack_key: NonEmptyText | None = None
    tool_name: NonEmptyText | None = None
    arguments: list[NonEmptyText] = Field(default_factory=list[str])


class ToolsResult(_Strict):
    """The result of one tools run, for the CLI and for later consumers.

    ``engine`` and ``verdicts`` are the native summaries, with the same run id. ``contexts`` and
    ``verdicts.results`` follow the planned order. ``reproduction`` maps each attack key to the
    argument list that runs its mold again; rendering it for a shell belongs to presentation.
    """

    mode: Literal["tools"] = "tools"
    run_id: NonEmptyText
    inventory: ToolsInventory
    contexts: list[AttackContext]
    engine: RunSummary
    verdicts: VerdictSummary
    executed: bool
    diagnostics: list[ToolsDiagnostic] = Field(default_factory=list[ToolsDiagnostic])
    reproduction: dict[str, list[NonEmptyText]] = Field(default_factory=dict[str, list[str]])
    exit_code: ExitCode

    @property
    def result_order(self) -> list[str]:
        return [context.attack_key for context in self.contexts]

    @property
    def has_gated_findings(self) -> bool:
        return self.verdicts.has_gated_findings
