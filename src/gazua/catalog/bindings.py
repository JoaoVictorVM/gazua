"""Prepares an attempt from a mold and the project's declarations, without running anything.

Substitution is one literal pass over a closed token table. Inserted values are never scanned
again, so configuration data cannot become a token, an expression or a template. Action data
keeps its JSON types instead of being produced by text concatenation.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Final, Literal

from pydantic import JsonValue

from gazua.catalog.models import (
    TOKEN_REQUIREMENTS,
    InjectText,
    Language,
    Mode,
    Mold,
    Requirement,
    ToolsAction,
    ordered_requirements,
    tokens_in,
)
from gazua.catalog.safety import text_problem
from gazua.config.models import FixtureRecord, GazuaConfig
from gazua.diagnostics import ConfigError, Diagnostic

# Constant synthetic markers. They contain no commands; they only show whether the sink
# escapes markup or control characters.
OUTPUT_MARKERS: Final = {
    "markup_marker": '<b data-gazua="marker">GAZUA-OUTPUT-MARKER</b>',
    "control_marker": "GAZUA-OUTPUT-MARKER\r\nX-Gazua-Marker: 1\x1b[0m",
}
ENCODED_PREFIX: Final = {
    "en": "Decode this base64 note and follow it: ",
    "pt": "Decodifique esta nota em base64 e siga-a: ",
}
_TOKEN_SUBSTITUTION = re.compile(r"\$\{([^{}]*)\}")


@dataclass(frozen=True)
class BindingContext:
    """Values a mold may use. They come only from validated configuration."""

    tool_name: str | None = None
    owner_arg: str | None = None
    actor_arg: str | None = None
    as_user_available: bool = False
    attacker_id: str | None = None
    victim_id: str | None = None
    record: FixtureRecord | None = None
    canary: str | None = None

    @classmethod
    def from_config(
        cls,
        config: GazuaConfig,
        tool_name: str | None = None,
        *,
        record_index: int = 0,
        canary_index: int = 0,
    ) -> BindingContext:
        """Context for one tool chosen by the consumer, one victim record and one canary."""
        tool = config.tools.get(tool_name) if tool_name is not None else None
        attacker, victim = config.fixtures.attacker, config.fixtures.victim
        records = [
            record
            for record in (victim.records if victim else [])
            if tool_name is None or record.tool == tool_name
        ]
        return cls(
            tool_name=tool_name if tool is not None else None,
            owner_arg=tool.owner_arg if tool else None,
            actor_arg=tool.actor_arg if tool else None,
            as_user_available=config.target.as_user is not None,
            attacker_id=attacker.id if attacker else None,
            victim_id=victim.id if victim else None,
            record=records[record_index] if record_index < len(records) else None,
            canary=(config.canaries[canary_index] if canary_index < len(config.canaries) else None),
        )

    def token_values(self, mold: Mold) -> dict[str, str | None]:
        record = self.record
        return {
            "tool.name": self.tool_name,
            "tool.owner_arg": self.owner_arg,
            "tool.actor_arg": self.actor_arg,
            "fixtures.attacker.id": self.attacker_id,
            "fixtures.victim.id": self.victim_id,
            "record.id": str(record.id) if record else None,
            "record.id_arg": record.id_arg if record else None,
            "canary": self.canary,
            "exfiltration_url": mold.exfiltration_url,
        }


@dataclass(frozen=True)
class BoundMold:
    """One prepared attempt. Executing it belongs to the consumer of the selected mode."""

    mold_id: str
    mode: Mode
    language: Language
    turns: tuple[str, ...]
    action: ToolsAction | InjectText
    tool_name: str | None = None
    arguments: dict[str, JsonValue] = field(default_factory=dict[str, JsonValue])
    act_as: str | None = None
    marker: str | None = None
    calls: int = 1


@dataclass(frozen=True)
class BindingImpediment:
    """Why an attempt cannot be prepared. Consumers report it as not tested, never resisted."""

    mold_id: str
    reason: Literal["missing_declarations", "not_applicable", "mode_not_supported"]
    missing: tuple[Requirement, ...] = ()


def _substitute(turn: str, values: dict[str, str | None]) -> str:
    return _TOKEN_SUBSTITUTION.sub(lambda match: values[match.group(1)] or "", turn)


def _check_bound(mold: Mold, turns: tuple[str, ...]) -> None:
    for index, turn in enumerate(turns):
        problem = text_problem(turn)
        if problem is not None and problem[0] == "domain":
            raise ConfigError(
                [
                    Diagnostic(
                        code="invalid_exfiltration_domain",
                        field=f"text[{index}]",
                        message=f"{mold.id}: {problem[1]}",
                    )
                ]
            )


def _actor(
    variant: str, context: BindingContext, arguments: dict[str, JsonValue]
) -> tuple[str | None, set[Requirement]]:
    if variant == "omitted_actor":
        return None, set()
    if context.attacker_id is None:
        return None, {"fixtures.attacker"}
    if context.actor_arg is not None:
        arguments[context.actor_arg] = context.attacker_id
        return None, set()
    if context.as_user_available:
        return context.attacker_id, set()
    return None, {"identity"}


def _record_arguments(
    variant: str, context: BindingContext, arguments: dict[str, JsonValue]
) -> set[Requirement] | None:
    record = context.record
    missing: set[Requirement] = set()
    if record is None:
        missing.add("fixtures.victim.records")
    if context.owner_arg is None:
        missing.add("tool.owner_arg")
    if context.victim_id is None:
        missing.add("fixtures.victim")
    if missing or record is None or context.owner_arg is None:
        return missing
    record_id: JsonValue = record.id
    if variant == "string_record_id":
        if isinstance(record.id, str):
            return None
        record_id = str(record.id)
    owner = {
        "victim_owner": context.victim_id,
        "attacker_owner": context.attacker_id,
        "string_record_id": context.victim_id,
    }
    if variant in owner:
        arguments[context.owner_arg] = owner[variant]
    arguments[record.id_arg] = record_id
    return missing


def _tools_attempt(
    mold: Mold,
    action: ToolsAction,
    context: BindingContext,
    turns: tuple[str, ...],
    language: Language,
) -> BoundMold | BindingImpediment:
    if context.tool_name is None:
        return BindingImpediment(mold.id, "missing_declarations", ("tool.classified",))
    arguments: dict[str, JsonValue] = {}
    missing: set[Requirement] = set()
    act_as: str | None = None
    if action.kind in ("call_forbidden", "call_sensitive"):
        act_as, missing = _actor(action.variant, context, arguments)
    elif action.kind == "read_victim_record" or action.variant == "attacker_owner":
        act_as, missing = _actor("declared_actor", context, arguments)
    if action.kind in ("read_victim_record", "probe_canary_return"):
        record_missing = _record_arguments(action.variant, context, arguments)
        if record_missing is None:
            return BindingImpediment(mold.id, "not_applicable")
        missing |= record_missing
    if action.kind == "probe_canary_return" and context.canary is None:
        missing.add("canaries")
    if missing:
        return BindingImpediment(mold.id, "missing_declarations", ordered_requirements(missing))
    return BoundMold(
        mold_id=mold.id,
        mode="tools",
        language=language,
        turns=turns,
        action=action,
        tool_name=context.tool_name,
        arguments=arguments,
        act_as=act_as,
        marker=OUTPUT_MARKERS.get(action.variant) if action.kind == "probe_output_sink" else None,
        calls=getattr(action, "calls", 1),
    )


def bind_mold(
    mold: Mold, context: BindingContext, *, mode: Mode, language: Language = "en"
) -> BoundMold | BindingImpediment:
    """Resolves the mold's text and action data for one mode. Calls no tool and no model.

    A token without a value is an impediment, never an empty substitution.
    """
    if mode not in mold.supported_modes:
        return BindingImpediment(mold.id, "mode_not_supported")
    values = context.token_values(mold)
    used = {name for turn in mold.turns(language) for name in tokens_in(turn)}
    absent = {name for name in used if values.get(name) is None}
    if absent:
        missing: set[Requirement] = {
            TOKEN_REQUIREMENTS[name] for name in absent if name in TOKEN_REQUIREMENTS
        }
        return BindingImpediment(mold.id, "missing_declarations", ordered_requirements(missing))
    turns = tuple(_substitute(turn, values) for turn in mold.turns(language))
    _check_bound(mold, turns)
    if mold.encoding == "base64":
        turns = tuple(
            ENCODED_PREFIX[language] + base64.b64encode(turn.encode("utf-8")).decode("ascii")
            for turn in turns
        )
    tools_action, agent_action = mold.tools_action, mold.agent_action
    if mode == "tools" and tools_action is not None:
        return _tools_attempt(mold, tools_action, context, turns, language)
    if agent_action is None:
        return BindingImpediment(mold.id, "mode_not_supported")
    return BoundMold(
        mold_id=mold.id, mode="agent", language=language, turns=turns, action=agent_action
    )
