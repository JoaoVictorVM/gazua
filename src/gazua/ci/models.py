"""Versioned CI contracts: the run summary, the pull request comment and their limits.

They hold identifiers, enumerations, counts and an already checked command, never free text.
A field added to these models changes the published contract and needs a new version.
"""

from __future__ import annotations

import json
import re
from typing import Annotated, Any, Final, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, model_validator

from gazua.catalog.models import Damage, Mode
from gazua.config.models import SCHEMA_DIALECT, Severity

CI_SUMMARY_SCHEMA_FILE: Final = "ci-summary-v1.schema.json"
PR_COMMENT_SCHEMA_FILE: Final = "pr-comment-v1.schema.json"
SARIF_PROFILE_SCHEMA_FILE: Final = "gazua-sarif-v1.schema.json"
SARIF_PROFILE: Final = "gazua-sarif-v1"
# The revision of the Action's contract with this module; action.yml declares the one it needs.
ACTION_CONTRACT: Final = 1
COMMENT_MARKER: Final = "<!-- gazua-ci-comment:v1 -->"
CI_FOLDER: Final = "ci"
MAX_FINDINGS: Final = 10_000
MAX_TOOL_NAME: Final = 200
MAX_REPRODUCTION_TOKENS: Final = 32
MAX_TOKEN_LENGTH: Final = 512
COMMENT_LIMIT_BYTES: Final = 60 * 1024
SARIF_MAX_RESULTS: Final = 10_000
SARIF_MAX_BYTES: Final = 32 * 1024 * 1024
SEVERITY_RANK: Final[dict[str, int]] = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SCHEMA_BASE: Final = "https://raw.githubusercontent.com/JoaoVictorVM/gazua/main/src/gazua/schemas/"

# Tool names and command tokens are restricted to characters that are inert in Markdown,
# SARIF viewers and terminals; anything else is omitted instead of escaped.
TOOL_NAME_PATTERN: Final = r"^[A-Za-z0-9_][A-Za-z0-9_.:/-]{0,199}$"
TOKEN_PATTERN: Final = r"^[A-Za-z0-9_.,:=/@+-]{1,512}$"  # noqa: S105
TOOL_NAME: Final = re.compile(TOOL_NAME_PATTERN)
TOKEN: Final = re.compile(TOKEN_PATTERN)

FindingId = Annotated[str, Field(pattern=r"^finding-[0-9a-f]{64}$")]
RunId = Annotated[str, Field(pattern=r"^GAZUA-[A-Za-z0-9-]+$", max_length=128)]
Code = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$", max_length=64)]
Count = Annotated[int, Field(ge=0)]
ToolName = Annotated[str, Field(pattern=TOOL_NAME_PATTERN)]
Token = Annotated[str, Field(pattern=TOKEN_PATTERN)]
ExitCode: TypeAlias = Literal[0, 1, 2]
FindingStatus: TypeAlias = Literal["new", "open"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


def _command_problem(tokens: list[str] | None, mode: str) -> bool:
    if tokens is None:
        return False
    return tokens[:3] != ["gazua", "run", f"--{mode}"]


def _ordered(ids: list[tuple[str, str]]) -> bool:
    keys = [(SEVERITY_RANK[severity], finding) for severity, finding in ids]
    return keys == sorted(keys) and len({finding for _, finding in ids}) == len(ids)


class CiFinding(_Strict):
    """One observed finding as CI shows it."""

    id: FindingId
    severity: Severity
    damage: Damage
    mode: Mode
    tool: ToolName | None
    status: FindingStatus | None
    regression: bool
    effective_gated: bool
    reproduction: (
        Annotated[list[Token], Field(min_length=3, max_length=MAX_REPRODUCTION_TOKENS)] | None
    )

    @model_validator(mode="after")
    def _consistent(self) -> CiFinding:
        if _command_problem(self.reproduction, self.mode):
            raise ValueError("A reproduction runs gazua run in the finding's mode.")
        if self.regression and self.status != "new":
            raise ValueError("A regression is a new finding whose entry was closed.")
        if self.status == "open" and self.effective_gated:
            raise ValueError("A known finding never gates.")
        return self


class CiSummary(_Strict):
    """The minimal projection of one run, shared by the comment, the job summary and SARIF."""

    model_config = ConfigDict(title="Gazua CI summary")

    schema_version: Literal[1]
    run_id: RunId
    gazua_version: Annotated[str, Field(max_length=128)] | None
    mode: Mode
    effective_exit_code: ExitCode
    baseline: bool
    new_findings: Count
    known_findings: Count
    not_tested: Count
    not_applicable: Count
    findings: Annotated[list[CiFinding], Field(max_length=MAX_FINDINGS)]
    diagnostics: list[Code]

    @model_validator(mode="after")
    def _consistent(self) -> CiSummary:
        if not _ordered([(item.severity, item.id) for item in self.findings]):
            raise ValueError("Findings are unique and ordered by severity and id.")
        if any(item.mode != self.mode for item in self.findings):
            raise ValueError("Every finding has the run's mode.")
        statuses = [item.status for item in self.findings]
        if self.baseline:
            if None in statuses:
                raise ValueError("With a baseline, every finding is new or open.")
            new = statuses.count("new")
        else:
            if any(item is not None for item in statuses):
                raise ValueError("Without a baseline no finding has a status.")
            if any(item.regression for item in self.findings):
                raise ValueError("Without a baseline there is no regression.")
            new = len(statuses)
        if (self.new_findings, self.known_findings) != (new, statuses.count("open")):
            raise ValueError("Counts are taken from the findings.")
        if self.diagnostics != sorted(set(self.diagnostics)):
            raise ValueError("Diagnostics are unique and ordered.")
        gated = any(item.effective_gated for item in self.findings)
        if self.effective_exit_code != 2 and self.effective_exit_code != int(gated):
            raise ValueError("Only an effectively gated finding fails the run.")
        return self


class CommentCounts(_Strict):
    new: Count
    known: Count
    not_tested: Count


class CommentFinding(_Strict):
    id: FindingId
    severity: Severity
    damage: Damage
    tool: ToolName | None
    status: FindingStatus | None
    regression: bool
    reproduction: (
        Annotated[list[Token], Field(min_length=3, max_length=MAX_REPRODUCTION_TOKENS)] | None
    )


class CommentDocument(_Strict):
    """What the pull request comment shows, validated before any Markdown is written.

    There is no message or metadata field on purpose: free text cannot reach the renderer.
    """

    model_config = ConfigDict(title="Gazua pull request comment")

    schema_version: Literal[1]
    run_id: RunId
    exit_code: ExitCode
    counts: CommentCounts
    findings: Annotated[list[CommentFinding], Field(max_length=MAX_FINDINGS)]

    @model_validator(mode="after")
    def _consistent(self) -> CommentDocument:
        if not _ordered([(item.severity, item.id) for item in self.findings]):
            raise ValueError("Findings are unique and ordered by severity and id.")
        statuses = [item.status for item in self.findings]
        new = statuses.count("new") if None not in statuses else len(statuses)
        if (self.counts.new, self.counts.known) != (new, statuses.count("open")):
            raise ValueError("Counts are taken from the findings.")
        return self


def _schema(model: type[BaseModel], name: str) -> dict[str, Any]:
    schema = model.model_json_schema(mode="validation")
    return {"$schema": SCHEMA_DIALECT, "$id": SCHEMA_BASE + name, **schema}


def build_ci_summary_schema() -> dict[str, Any]:
    return _schema(CiSummary, CI_SUMMARY_SCHEMA_FILE)


def build_pr_comment_schema() -> dict[str, Any]:
    return _schema(CommentDocument, PR_COMMENT_SCHEMA_FILE)


def render_schema(schema: dict[str, Any]) -> str:
    return json.dumps(schema, indent=2) + "\n"


def summary_json(summary: CiSummary) -> str:
    return json.dumps(summary.model_dump(mode="json"), indent=2, ensure_ascii=True) + "\n"


def packaged_schema(name: str) -> str:
    """A schema distributed with this package, read without network access."""
    from importlib.resources import files

    return files("gazua").joinpath(f"schemas/{name}").read_text(encoding="utf-8")
