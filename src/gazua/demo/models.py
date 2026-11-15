"""Contracts of the demo: options, the workspace manifest, the store state and the result."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field

ExitCode: TypeAlias = Literal[0, 1, 2]
DemoMode: TypeAlias = Literal["tools", "agent"]
BrowserOutcome: TypeAlias = Literal["opened", "skipped", "failed", "not_reached"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class DemoOptions(_Strict):
    """The same three choices the command line offers."""

    output: Annotated[str, Field(min_length=1)] = "gazua-demo"
    no_open: bool = False
    language: Literal["en", "pt"] = "en"


class DemoManifest(_Strict):
    """Marks a folder as a demo workspace and pins the configuration it holds.

    It authenticates nothing and never names code to import: the coordinator only uses the
    packaged references it already knows.
    """

    schema_version: Literal[1]
    profile: Literal["gazua-store-demo"]
    profile_version: Annotated[int, Field(gt=0)]
    config_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


@dataclass(slots=True)
class StoreState:
    """The demo store of one attempt. It lives in memory and is rebuilt by ``reset``."""

    users: dict[str, dict[str, str]]
    orders: dict[str, dict[str, Any]]
    refunds: list[dict[str, Any]]
    outbox: list[dict[str, Any]]
    accepted_markers: list[str]
    history: list[str]


@dataclass(frozen=True, slots=True)
class ModeOutcome:
    """One mode of the demo: its native result, its exit code and where its reports went."""

    mode: DemoMode
    started: bool
    exit_code: ExitCode | None
    run_id: str | None = None
    archive: Path | None = None
    reports: dict[str, Path] = field(default_factory=dict[str, Path])
    findings: int = 0
    native: Any = None
    reason: str | None = None

    def projection(self) -> dict[str, Any]:
        found: dict[str, Any] = {"started": self.started, "exit_code": self.exit_code}
        if self.reason is not None:
            found["reason"] = self.reason
        return found


@dataclass(frozen=True, slots=True)
class DemoResult:
    """What one demo did. It is internal, not a third format of findings."""

    workspace: Path
    index: Path | None
    tools: ModeOutcome
    agent: ModeOutcome
    browser: BrowserOutcome
    exit_code: ExitCode

    def projection(self) -> dict[str, Any]:
        return {
            "workspace": str(self.workspace),
            "index": None if self.index is None else str(self.index),
            "tools": self.tools.projection(),
            "agent": self.agent.projection(),
            "browser": self.browser,
            "exit_code": self.exit_code,
        }


__all__ = [
    "BrowserOutcome",
    "DemoManifest",
    "DemoMode",
    "DemoOptions",
    "DemoResult",
    "ExitCode",
    "ModeOutcome",
    "StoreState",
]
