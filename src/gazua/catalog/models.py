"""Versioned attack mold format: the single source of the loader and of the JSON Schema.

A mold is data only. Actions, requirements and success signals are closed enumerations with
fixed meaning in the consumers, so a mold cannot carry code, expressions or tool names.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from importlib.resources import files
from typing import Annotated, Any, Final, Literal, LiteralString, TypeAlias, TypeVar, get_args

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Discriminator,
    Field,
    Tag,
    WithJsonSchema,
    model_validator,
)
from pydantic_core import PydanticCustomError

from gazua.catalog.safety import exfiltration_url_problem, text_problem
from gazua.config.models import SCHEMA_DIALECT, Severity

MOLD_SCHEMA_VERSION = 1
MOLD_SCHEMA_URL = (
    "https://raw.githubusercontent.com/JoaoVictorVM/gazua/main/"
    "src/gazua/schemas/mold-v1.schema.json"
)
ID_PATTERN = r"^[a-z][a-z0-9-]{0,79}$"
MAX_TURN_CHARACTERS = 16_384
REPEATED_CALLS: Final = 51

Damage: TypeAlias = Literal[
    "prompt_only_permission",
    "secret_in_context",
    "idor_via_agent",
    "unhandled_output",
    "unlocked_memory",
    "unchecked_spending",
]
Entry: TypeAlias = Literal[
    "user_message",
    "tool_result",
    "rag_document",
    "poisoned_memory",
    "web_page",
    "attachment",
    "mcp_tool_description",
]
Technique: TypeAlias = Literal[
    "fake_authority", "delimiter_break", "portuguese", "invisible_text", "encoding", "two_turn"
]
Mode: TypeAlias = Literal["tools", "agent"]
Language: TypeAlias = Literal["en", "pt"]
Signal: TypeAlias = Literal[
    "forbidden_tool_call",
    "sensitive_tool_call",
    "canary_in_response",
    "canary_in_tool_arguments",
    "receiver_hit",
    "victim_record_access",
    "output_sink_effect",
    "memory_effect",
    "tool_call_ceiling",
]
Requirement: TypeAlias = Literal[
    "tool.forbidden",
    "tool.sensitive",
    "tool.safe",
    "tool.classified",
    "tool.owner_arg",
    "identity",
    "fixtures.attacker",
    "fixtures.victim",
    "fixtures.victim.records",
    "canaries",
    "output_sink",
    "target.reset",
    "direct_tool_access",
    "entry_supported",
]

DAMAGES: tuple[Damage, ...] = get_args(Damage)
ENTRIES: tuple[Entry, ...] = get_args(Entry)
TECHNIQUES: tuple[Technique, ...] = get_args(Technique)
MODES: tuple[Mode, ...] = get_args(Mode)
REQUIREMENTS: tuple[Requirement, ...] = get_args(Requirement)
RUNTIME_REQUIREMENTS: frozenset[Requirement] = frozenset({"direct_tool_access", "entry_supported"})

DEFAULT_SEVERITY: dict[Damage, Severity] = {
    "prompt_only_permission": "critical",
    "secret_in_context": "critical",
    "idor_via_agent": "high",
    "unhandled_output": "high",
    "unlocked_memory": "high",
    "unchecked_spending": "medium",
}
DAMAGE_SIGNALS: dict[Damage, frozenset[Signal]] = {
    "prompt_only_permission": frozenset({"forbidden_tool_call", "sensitive_tool_call"}),
    "secret_in_context": frozenset(
        {"canary_in_response", "canary_in_tool_arguments", "receiver_hit"}
    ),
    "idor_via_agent": frozenset({"victim_record_access"}),
    "unhandled_output": frozenset({"output_sink_effect"}),
    "unlocked_memory": frozenset({"memory_effect"}),
    "unchecked_spending": frozenset({"sensitive_tool_call", "tool_call_ceiling"}),
}

# Exfiltration and fixture values come only from validated configuration or from the mold's
# reserved destination. The table is closed: an unknown name is an authoring error.
TOKENS: tuple[str, ...] = (
    "tool.name",
    "tool.owner_arg",
    "tool.actor_arg",
    "fixtures.attacker.id",
    "fixtures.victim.id",
    "record.id",
    "record.id_arg",
    "canary",
    "exfiltration_url",
)
TOKEN_REQUIREMENTS: dict[str, Requirement] = {
    "tool.owner_arg": "tool.owner_arg",
    "tool.actor_arg": "identity",
    "fixtures.attacker.id": "fixtures.attacker",
    "fixtures.victim.id": "fixtures.victim",
    "record.id": "fixtures.victim.records",
    "record.id_arg": "fixtures.victim.records",
    "canary": "canaries",
}
_TOKEN = re.compile(r"\$\{([^{}]*)\}")
_DOMAIN_MESSAGE: Final = "Only .gazua.test exfiltration destinations are allowed."

_Item = TypeVar("_Item")


def _invalid(
    code: LiteralString, message: LiteralString, context: dict[str, Any] | None = None
) -> PydanticCustomError:
    return PydanticCustomError(code, message, context)


def tokens_in(text: str) -> list[str]:
    return _TOKEN.findall(text)


def ordered_requirements(items: Iterable[Requirement]) -> tuple[Requirement, ...]:
    chosen = set(items)
    return tuple(item for item in REQUIREMENTS if item in chosen)


def _check_unique(values: list[_Item]) -> list[_Item]:
    if any(value in values[:index] for index, value in enumerate(values)):
        raise _invalid("duplicate_item", "Items in this list must be unique.")
    return values


def _check_turn(value: str) -> str:
    if "\x00" in value:
        raise _invalid("invalid_text", "Text cannot contain NUL characters.")
    if _TOKEN.sub("", value).count("${"):
        raise _invalid("mold_binding", "Unterminated ${...} token.")
    for name in tokens_in(value):
        if name not in TOKENS:
            raise _invalid("mold_binding", "Unknown ${...} token; see the allowed token list.")
    problem = text_problem(value)
    if problem is not None:
        kind, _message = problem
        if kind == "domain":
            raise _invalid("exfiltration_domain", _DOMAIN_MESSAGE)
        raise _invalid(
            "opaque_payload",
            "Encoded or opaque payloads are not accepted; "
            "write the plain text and set encoding: base64.",
        )
    return value


def _check_exfiltration_url(value: str) -> str:
    if exfiltration_url_problem(value) is not None:
        raise _invalid("exfiltration_domain", _DOMAIN_MESSAGE)
    return value


Turn = Annotated[
    str,
    Field(min_length=1, max_length=MAX_TURN_CHARACTERS),
    AfterValidator(_check_turn),
]
Turns = Annotated[list[Turn], Field(min_length=1, max_length=2)]
MoldId = Annotated[str, Field(pattern=ID_PATTERN, max_length=80)]
ExfiltrationUrl = Annotated[
    str,
    AfterValidator(_check_exfiltration_url),
    WithJsonSchema(
        {
            "type": "string",
            "pattern": (
                r"^https?://(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+gazua\.test"
                r"(?:/[^#\s]*)?$"
            ),
        }
    ),
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


ActorVariant: TypeAlias = Literal["declared_actor", "omitted_actor"]
OwnerVariant: TypeAlias = Literal["victim_owner", "attacker_owner", "omitted_owner"]


class CallForbidden(_Strict):
    """Calls a tool declared ``forbidden`` directly, as the attacker or without an actor."""

    kind: Literal["call_forbidden"]
    variant: ActorVariant


class CallSensitive(_Strict):
    """Calls a tool declared ``sensitive`` directly, as the attacker or without an actor."""

    kind: Literal["call_sensitive"]
    variant: ActorVariant


class ReadVictimRecord(_Strict):
    """Reads a victim fixture record as the attacker."""

    kind: Literal["read_victim_record"]
    variant: Literal["victim_owner", "attacker_owner", "omitted_owner", "string_record_id"]


class ProbeCanaryReturn(_Strict):
    """Reads a test record and checks whether the configured canary comes back."""

    kind: Literal["probe_canary_return"]
    variant: OwnerVariant


class ProbeOutputSink(_Strict):
    """Sends a constant Gazua marker to the declared output sink."""

    kind: Literal["probe_output_sink"]
    variant: Literal["markup_marker", "control_marker"]


class RepeatSensitiveCall(_Strict):
    """Repeats a sensitive call past the default ceiling, always under the configured limits."""

    kind: Literal["repeat_sensitive_call"]
    variant: Literal["repeated"]

    @property
    def calls(self) -> int:
        return REPEATED_CALLS


ToolsAction: TypeAlias = Annotated[
    CallForbidden
    | CallSensitive
    | ReadVictimRecord
    | ProbeCanaryReturn
    | ProbeOutputSink
    | RepeatSensitiveCall,
    Field(discriminator="kind"),
]
ToolsActionKind: TypeAlias = Literal[
    "call_forbidden",
    "call_sensitive",
    "read_victim_record",
    "probe_canary_return",
    "probe_output_sink",
    "repeat_sensitive_call",
]


class InjectText(_Strict):
    """Delivers the mold's turns to the declared entry, in one isolated session."""

    kind: Literal["inject_text"]


class DualAction(_Strict):
    """Action of a mold that supports both modes: one intention per mode."""

    tools: ToolsAction
    agent: InjectText


def _action_tag(value: Any) -> str:
    if isinstance(value, dict):
        kind = value.get("kind")  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        if kind is None:
            return "dual"
        return "agent" if kind == "inject_text" else "tools"
    if isinstance(value, DualAction):
        return "dual"
    return "agent" if isinstance(value, InjectText) else "tools"


Action: TypeAlias = Annotated[
    Annotated[ToolsAction, Tag("tools")]
    | Annotated[InjectText, Tag("agent")]
    | Annotated[DualAction, Tag("dual")],
    Discriminator(_action_tag),
]

TOOLS_SIGNAL: dict[ToolsActionKind, Signal] = {
    "call_forbidden": "forbidden_tool_call",
    "call_sensitive": "sensitive_tool_call",
    "read_victim_record": "victim_record_access",
    "probe_canary_return": "canary_in_response",
    "probe_output_sink": "output_sink_effect",
    "repeat_sensitive_call": "tool_call_ceiling",
}
SIGNAL_REQUIREMENTS: dict[Signal, frozenset[Requirement]] = {
    "forbidden_tool_call": frozenset({"tool.forbidden"}),
    "sensitive_tool_call": frozenset({"tool.sensitive"}),
    "tool_call_ceiling": frozenset({"tool.sensitive"}),
    "canary_in_response": frozenset({"canaries"}),
    "canary_in_tool_arguments": frozenset({"canaries"}),
    "receiver_hit": frozenset({"canaries"}),
    "victim_record_access": frozenset(
        {
            "tool.owner_arg",
            "identity",
            "fixtures.attacker",
            "fixtures.victim",
            "fixtures.victim.records",
        }
    ),
    "output_sink_effect": frozenset({"output_sink"}),
    "memory_effect": frozenset({"target.reset", "entry_supported"}),
}
TOOLS_MINIMUM: frozenset[Requirement] = frozenset(
    {"tool.safe", "tool.classified", "direct_tool_access"}
)
_ACTION_REQUIREMENTS: dict[str, frozenset[Requirement]] = {
    "declared_actor": frozenset({"identity", "fixtures.attacker"}),
    "probe_canary_return": frozenset({"tool.owner_arg", "fixtures.victim.records"}),
    "attacker_owner": frozenset({"identity", "fixtures.attacker"}),
}


class MoldText(_Strict):
    """Attack text by language. Both languages are required and have the same turns."""

    en: Turns
    pt: Turns


class Success(_Strict):
    """What a consumer must observe in code to call the attack effective."""

    signal: Signal


class Mold(_Strict):
    """One attack: damage + entry + technique, with its text, action and success signal."""

    model_config = ConfigDict(title="Gazua attack mold")

    schema_version: Literal[1]
    id: MoldId
    damage: Damage
    entry: Entry
    technique: Technique
    severity: Severity | None = None
    supported_modes: Annotated[
        list[Mode], Field(min_length=1, max_length=2), AfterValidator(_check_unique)
    ] = Field(json_schema_extra={"uniqueItems": True})
    text: MoldText
    required_declarations: Annotated[list[Requirement], AfterValidator(_check_unique)] = Field(
        default_factory=list["Requirement"], json_schema_extra={"uniqueItems": True}
    )
    action: Action
    success: Success
    exfiltration_url: ExfiltrationUrl | None = None
    encoding: Literal["base64"] | None = None

    @model_validator(mode="after")
    def _relations(self) -> Mold:
        problem = relation_problem(self)
        if problem is not None:
            path, message = problem
            raise PydanticCustomError("mold_relation", message, {"path": path})
        return self

    @property
    def effective_severity(self) -> Severity:
        return self.severity or DEFAULT_SEVERITY[self.damage]

    @property
    def modes(self) -> tuple[Mode, ...]:
        return tuple(mode for mode in MODES if mode in self.supported_modes)

    @property
    def tools_action(self) -> ToolsAction | None:
        if isinstance(self.action, DualAction):
            return self.action.tools
        return None if isinstance(self.action, InjectText) else self.action

    @property
    def agent_action(self) -> InjectText | None:
        if isinstance(self.action, DualAction):
            return self.action.agent
        return self.action if isinstance(self.action, InjectText) else None

    def turns(self, language: Language) -> tuple[str, ...]:
        return tuple(self.text.en if language == "en" else self.text.pt)

    @property
    def tokens(self) -> frozenset[str]:
        return frozenset(
            name for turn in (*self.text.en, *self.text.pt) for name in tokens_in(turn)
        )

    @property
    def effective_requirements(self) -> tuple[Requirement, ...]:
        """Declared requirements plus the minimums of the mold's modes, action and signal.

        A mold can add requirements but cannot remove these, so third-party content cannot
        relax the protections that tools mode depends on.
        """
        required: set[Requirement] = set(self.required_declarations)
        required |= SIGNAL_REQUIREMENTS[self.success.signal]
        required |= {TOKEN_REQUIREMENTS[name] for name in self.tokens if name in TOKEN_REQUIREMENTS}
        tools_action = self.tools_action
        if tools_action is not None:
            required |= TOOLS_MINIMUM | SIGNAL_REQUIREMENTS[TOOLS_SIGNAL[tools_action.kind]]
            required |= _ACTION_REQUIREMENTS.get(tools_action.kind, frozenset())
            required |= _ACTION_REQUIREMENTS.get(tools_action.variant, frozenset())
        if self.agent_action is not None:
            required.add("entry_supported")
        return ordered_requirements(required)


def relation_problem(mold: Mold) -> tuple[tuple[str | int, ...], LiteralString] | None:
    """The first rule between fields that the mold breaks, as ``(path, message)``."""
    if len(mold.text.en) != len(mold.text.pt):
        return ("text", "pt"), "EN and PT text must have the same number of turns."
    expected_turns = 2 if mold.technique == "two_turn" else 1
    if len(mold.text.en) != expected_turns:
        return ("text", "en"), "The two_turn technique uses exactly two turns; others use one."
    shape = _action_tag(mold.action)
    expected_shape = "dual" if len(mold.supported_modes) == 2 else mold.supported_modes[0]
    if shape != expected_shape:
        return ("action",), "The action must match supported_modes: one intention per mode."
    if mold.success.signal not in DAMAGE_SIGNALS[mold.damage]:
        return ("success", "signal"), "This success signal does not prove this damage."
    tools_action = mold.tools_action
    if tools_action is not None:
        kind_path: tuple[str, ...] = (
            ("action", "tools", "kind") if shape == "dual" else ("action", "kind")
        )
        if mold.damage == "unlocked_memory":
            return ("supported_modes",), "Memory attacks have no direct tool action yet."
        if TOOLS_SIGNAL[tools_action.kind] != mold.success.signal:
            return kind_path, "This tools action cannot produce the declared success signal."
    if mold.encoding is not None and (mold.technique != "encoding" or mold.agent_action is None):
        return ("encoding",), "encoding applies only to injected text with technique encoding."
    needs_destination = mold.success.signal == "receiver_hit" or "exfiltration_url" in mold.tokens
    if needs_destination and mold.exfiltration_url is None:
        return ("exfiltration_url",), "This mold uses a receiver; declare exfiltration_url."
    return None


def build_mold_json_schema() -> dict[str, Any]:
    schema = Mold.model_json_schema(mode="validation")
    return {"$schema": SCHEMA_DIALECT, "$id": MOLD_SCHEMA_URL, **schema}


def render_mold_json_schema() -> str:
    return json.dumps(build_mold_json_schema(), indent=2) + "\n"


def packaged_mold_json_schema() -> str:
    """The mold schema distributed with this package, read without network access."""
    resource = files("gazua").joinpath("schemas/mold-v1.schema.json")
    return resource.read_text(encoding="utf-8")
