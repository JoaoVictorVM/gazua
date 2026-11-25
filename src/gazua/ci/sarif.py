"""The Gazua profile of SARIF 2.1.0, built only from the CI summary.

Each observed finding is one result, fingerprinted by its finding id so text changes never
duplicate an alert. Not tested and not applicable scenarios are counts and fixed-code
notifications, never results. The location is the configuration file, with no invented line.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from gazua.catalog.models import DAMAGES, Damage, Mode
from gazua.ci.models import (
    SARIF_MAX_BYTES,
    SARIF_MAX_RESULTS,
    SARIF_PROFILE,
    SARIF_PROFILE_SCHEMA_FILE,
    SCHEMA_BASE,
    CiFinding,
    CiSummary,
    Code,
    Count,
    FindingId,
    RunId,
    Token,
    ToolName,
)
from gazua.config.models import SCHEMA_DIALECT, Severity

SARIF_SCHEMA_URI: Final = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI: Final = "https://github.com/JoaoVictorVM/gazua"
FINGERPRINT: Final = "gazuaFindingId/v1"
LEVELS: Final[dict[str, Literal["error", "warning", "note"]]] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}
RULE_NAMES: Final[dict[str, str]] = {
    "prompt_only_permission": "Permission enforced only by the prompt",
    "secret_in_context": "Secret reachable from the agent context",
    "idor_via_agent": "Another user's record reached through the agent",
    "unhandled_output": "Agent output reaches a sink without handling",
    "unlocked_memory": "Persistent memory written without control",
    "unchecked_spending": "Spending without a server-side limit",
}
NOTIFICATIONS: Final[dict[str, str]] = {
    "gazua_not_tested": "Some scenarios were not tested; they prove nothing.",
    "gazua_not_applicable": "Some scenarios did not apply to this target.",
    "gazua_operational_error": "The run had an operational error; results may be incomplete.",
}
RelativeUri = Annotated[
    str, Field(pattern=r"^[A-Za-z0-9_][A-Za-z0-9._-]*(/[A-Za-z0-9_][A-Za-z0-9._-]*)*$")
]
Level = Literal["error", "warning", "note"]


class SarifProfileError(Exception):
    def __init__(self, code: str = "sarif_profile_invalid") -> None:
        self.code = code
        super().__init__(code)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, populate_by_name=True)


class Text(_Strict):
    text: Annotated[str, Field(min_length=1, max_length=1024)]


class RuleProperties(_Strict):
    tags: list[Literal["security", "gazua"]]
    damage: Damage


class Rule(_Strict):
    id: Annotated[str, Field(pattern=r"^gazua/[a-z_]+$")]
    name: Annotated[str, Field(pattern=r"^[A-Za-z]+$")]
    shortDescription: Text
    helpUri: Literal["https://github.com/JoaoVictorVM/gazua/blob/main/docs/fix-guide.md"]
    properties: RuleProperties


class Driver(_Strict):
    name: Literal["Gazua"]
    informationUri: Literal["https://github.com/JoaoVictorVM/gazua"]
    semanticVersion: Annotated[str, Field(max_length=128)] | None = None
    rules: list[Rule]


class Tool(_Strict):
    driver: Driver


class ArtifactLocation(_Strict):
    uri: RelativeUri


class PhysicalLocation(_Strict):
    artifactLocation: ArtifactLocation


class Location(_Strict):
    physicalLocation: PhysicalLocation


class ResultProperties(_Strict):
    findingId: FindingId
    severity: Severity
    damage: Damage
    mode: Mode
    tool: ToolName | None = None
    regression: bool
    reproduction: Annotated[list[Token], Field(min_length=3, max_length=32)] | None = None


class Result(_Strict):
    ruleId: Annotated[str, Field(pattern=r"^gazua/[a-z_]+$")]
    level: Level
    message: Text
    baselineState: Literal["new", "unchanged"] | None = None
    partialFingerprints: dict[Literal["gazuaFindingId/v1"], FindingId]
    locations: Annotated[list[Location], Field(min_length=1, max_length=1)]
    properties: ResultProperties

    @model_validator(mode="after")
    def _consistent(self) -> Result:
        if self.partialFingerprints.get(FINGERPRINT) != self.properties.findingId:
            raise ValueError("The fingerprint is the finding id.")
        if self.ruleId != f"gazua/{self.properties.damage}":
            raise ValueError("The rule is the finding's damage.")
        if self.level != LEVELS[self.properties.severity]:
            raise ValueError("The level follows the severity.")
        return self


class Descriptor(_Strict):
    id: Code


class Notification(_Strict):
    descriptor: Descriptor
    message: Text
    level: Literal["note", "warning", "error"]


class InvocationProperties(_Strict):
    gazuaProfile: Literal["gazua-sarif-v1"]
    runId: RunId
    exitCode: Literal[0, 1, 2]
    newFindings: Count
    knownFindings: Count
    notTested: Count
    notApplicable: Count


class Invocation(_Strict):
    executionSuccessful: bool
    toolExecutionNotifications: list[Notification]
    properties: InvocationProperties


class RunProperties(_Strict):
    gazuaProfile: Literal["gazua-sarif-v1"]


class SarifRun(_Strict):
    tool: Tool
    invocations: Annotated[list[Invocation], Field(min_length=1, max_length=1)]
    results: Annotated[list[Result], Field(max_length=SARIF_MAX_RESULTS)]
    properties: RunProperties

    @model_validator(mode="after")
    def _consistent(self) -> SarifRun:
        rules = {item.id for item in self.tool.driver.rules}
        if rules != {f"gazua/{damage}" for damage in DAMAGES}:
            raise ValueError("Every damage has exactly one rule.")
        ids = [item.properties.findingId for item in self.results]
        if len(set(ids)) != len(ids):
            raise ValueError("Each finding is one result.")
        invocation = self.invocations[0]
        if invocation.executionSuccessful != (invocation.properties.exitCode != 2):
            raise ValueError("Only exit 0 or 1 is a successful execution.")
        return self


class SarifLog(_Strict):
    """The whole SARIF document of the Gazua profile."""

    model_config = ConfigDict(title="Gazua SARIF profile v1")

    schema_: Annotated[
        Literal["https://json.schemastore.org/sarif-2.1.0.json"], Field(alias="$schema")
    ]
    version: Literal["2.1.0"]
    runs: Annotated[list[SarifRun], Field(min_length=1, max_length=1)]


def _rule(damage: Damage) -> Rule:
    name = "".join(part.capitalize() for part in damage.split("_"))
    return Rule(
        id=f"gazua/{damage}",
        name=name,
        shortDescription=Text(text=RULE_NAMES.get(damage, damage)),
        helpUri="https://github.com/JoaoVictorVM/gazua/blob/main/docs/fix-guide.md",
        properties=RuleProperties(tags=["security", "gazua"], damage=damage),
    )


def _message(item: CiFinding) -> str:
    tool = item.tool if item.tool is not None else "no recorded tool"
    return f"Gazua finding {item.id}: {item.severity} {item.damage} in {tool}."


def _result(item: CiFinding, config_path: str) -> Result:
    state: Literal["new", "unchanged"] | None = None
    if item.status is not None:
        state = "new" if item.status == "new" else "unchanged"
    return Result(
        ruleId=f"gazua/{item.damage}",
        level=LEVELS[item.severity],
        message=Text(text=_message(item)),
        baselineState=state,
        partialFingerprints={FINGERPRINT: item.id},
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri=config_path)
                )
            )
        ],
        properties=ResultProperties(
            findingId=item.id,
            severity=item.severity,
            damage=item.damage,
            mode=item.mode,
            tool=item.tool,
            regression=item.regression,
            reproduction=item.reproduction,
        ),
    )


def _notifications(summary: CiSummary) -> list[Notification]:
    codes: list[str] = []
    if summary.not_tested:
        codes.append("gazua_not_tested")
    if summary.not_applicable:
        codes.append("gazua_not_applicable")
    if summary.effective_exit_code == 2:
        codes.append("gazua_operational_error")
    notices = [
        Notification(
            descriptor=Descriptor(id=code),
            message=Text(text=NOTIFICATIONS[code]),
            level="warning" if code == "gazua_operational_error" else "note",
        )
        for code in codes
    ]
    notices += [
        Notification(
            descriptor=Descriptor(id=code),
            message=Text(text="Projection diagnostic."),
            level="note",
        )
        for code in summary.diagnostics
    ]
    return notices


def build_sarif(summary: CiSummary, config_path: str = "gazua.yaml") -> SarifLog:
    """The SARIF document of one summary. Any inconsistency raises ``SarifProfileError``."""
    if len(summary.findings) > SARIF_MAX_RESULTS:
        raise SarifProfileError("sarif_too_many_results")
    try:
        return SarifLog(
            schema_=SARIF_SCHEMA_URI,
            version="2.1.0",
            runs=[
                SarifRun(
                    tool=Tool(
                        driver=Driver(
                            name="Gazua",
                            informationUri="https://github.com/JoaoVictorVM/gazua",
                            semanticVersion=summary.gazua_version,
                            rules=[_rule(damage) for damage in DAMAGES],
                        )
                    ),
                    invocations=[
                        Invocation(
                            executionSuccessful=summary.effective_exit_code != 2,
                            toolExecutionNotifications=_notifications(summary),
                            properties=InvocationProperties(
                                gazuaProfile=SARIF_PROFILE,
                                runId=summary.run_id,
                                exitCode=summary.effective_exit_code,
                                newFindings=summary.new_findings,
                                knownFindings=summary.known_findings,
                                notTested=summary.not_tested,
                                notApplicable=summary.not_applicable,
                            ),
                        )
                    ],
                    results=[_result(item, config_path) for item in summary.findings],
                    properties=RunProperties(gazuaProfile=SARIF_PROFILE),
                )
            ],
        )
    except ValidationError:
        raise SarifProfileError from None


def sarif_json(log: SarifLog) -> str:
    """Deterministic JSON within the size limit, checked again by parsing it back."""
    data = log.model_dump(mode="json", by_alias=True, exclude_none=True)
    text = json.dumps(data, indent=2, ensure_ascii=True) + "\n"
    if len(text.encode("utf-8")) > SARIF_MAX_BYTES:
        raise SarifProfileError("sarif_too_large")
    validate_sarif(text)
    return text


def validate_sarif(text: str) -> SarifLog:
    """The profile document parsed from JSON text, or ``SarifProfileError``."""
    try:
        data: Any = json.loads(text)
        return SarifLog.model_validate(data, strict=False)
    except (ValueError, ValidationError):
        raise SarifProfileError from None


def build_sarif_profile_schema() -> dict[str, Any]:
    schema = SarifLog.model_json_schema(mode="validation", by_alias=True)
    return {"$schema": SCHEMA_DIALECT, "$id": SCHEMA_BASE + SARIF_PROFILE_SCHEMA_FILE, **schema}
