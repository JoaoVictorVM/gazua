"""Inventory of the target's tools: what was declared, what was wrapped, and what can run.

Tools mode calls tools as the attacker, or with no actor when the attack leaves it out, through
this inventory. A tool that the declarations do not release is refused here, before any proxy
is reached, and nothing falls back to a real call.
"""

from __future__ import annotations

import asyncio
import inspect
import types
import typing
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from gazua.config.absences import tool_not_found
from gazua.config.models import GazuaConfig, Tool, ToolClass
from gazua.diagnostics import Diagnostic
from gazua.integration.errors import GazuaBlockedError
from gazua.integration.registry import RegisteredTool, registry
from gazua.runtime.session_models import AnySession, SessionActor
from gazua.runtime.session_writer import activate

Role = Literal["attacker", "victim"]


class InvocationRefused(GazuaBlockedError):
    """Gazua will not call this tool by name."""


class NotSafeToCall(InvocationRefused):
    """The declarations keep this tool in dry-run, so it cannot run for real."""

    def __init__(self) -> None:
        super().__init__("blocked_real_call")


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def _matches(value: object, annotation: object) -> bool | None:
    """Whether JSON data fits a return annotation; None when the annotation is not checkable."""
    if annotation is None or annotation is type(None):
        return value is None
    simple: dict[object, Callable[[object], bool]] = {
        str: lambda item: isinstance(item, str),
        bool: lambda item: isinstance(item, bool),
        int: lambda item: isinstance(item, int) and not isinstance(item, bool),
        float: lambda item: isinstance(item, int | float) and not isinstance(item, bool),
        list: lambda item: isinstance(item, list),
        dict: lambda item: isinstance(item, dict),
    }
    if annotation in simple:
        return simple[annotation](value)
    origin = typing.get_origin(annotation)
    arguments = typing.get_args(annotation)
    if origin is typing.Union or origin is types.UnionType:
        results = [_matches(value, member) for member in arguments]
        if any(result is True for result in results):
            return True
        return None if any(result is None for result in results) else False
    if origin is list and len(arguments) == 1:
        if not isinstance(value, list):
            return False
        return _all_match(typing.cast("list[object]", value), arguments[0])
    if origin is dict and len(arguments) == 2 and arguments[0] is str:
        if not isinstance(value, dict):
            return False
        return _all_match(list(typing.cast("dict[str, object]", value).values()), arguments[1])
    return None


def _all_match(items: list[object], annotation: object) -> bool | None:
    results = [_matches(item, annotation) for item in items]
    if any(result is False for result in results):
        return False
    return None if any(result is None for result in results) else True


def check_fidelity(function: Callable[..., Any], value: object) -> bool | None:
    """Compares ``dry_run_return`` with the return annotation of simple JSON types only."""
    try:
        hints = typing.get_type_hints(function)
    # Resolving annotations evaluates the target's code; failing only skips the check.
    except Exception:  # noqa: BLE001
        return None
    if "return" not in hints:
        return None
    return _matches(value, hints["return"])


@dataclass(frozen=True, slots=True)
class InventoryEntry:
    name: str
    declaration: Tool | None
    registered: RegisteredTool

    @property
    def dry_run(self) -> bool:
        return self.declaration is None or self.declaration.requires_dry_run


@dataclass(frozen=True, slots=True)
class ToolSummary:
    real: tuple[str, ...]
    dry_run: tuple[str, ...]
    low_fidelity: tuple[str, ...]
    warnings: tuple[Diagnostic, ...]

    @property
    def text(self) -> str:
        return f"{_plural(len(self.real), 'real tool')}, {len(self.dry_run)} in dry-run"

    def lines(self) -> list[str]:
        """What a run prints before the first attack."""
        lines = [self.text]
        if self.low_fidelity:
            lines.append(f"Low fidelity: {', '.join(self.low_fidelity)}")
        lines.extend(f"Warning: {warning.render()}" for warning in self.warnings)
        return lines


@dataclass(frozen=True, slots=True)
class ToolInventory:
    config: GazuaConfig
    entries: Mapping[str, InventoryEntry]
    declared_not_found: tuple[str, ...]
    registered_undeclared: tuple[str, ...]
    ambiguous: tuple[str, ...]
    low_fidelity: tuple[str, ...]
    diagnostics: tuple[Diagnostic, ...]

    @classmethod
    def collect(
        cls,
        config: GazuaConfig,
        registered: Mapping[str, tuple[RegisteredTool, ...]] | None = None,
    ) -> ToolInventory:
        """Reconciles the declared tools with the tools wrapped in this process."""
        found = registry.snapshot() if registered is None else registered
        entries: dict[str, InventoryEntry] = {}
        diagnostics: list[Diagnostic] = []
        ambiguous: list[str] = []
        low_fidelity: list[str] = []
        for name in sorted(found):
            candidates: tuple[RegisteredTool, ...] = found[name]
            if not candidates:
                continue
            if len(candidates) > 1:
                ambiguous.append(name)
                diagnostics.append(
                    Diagnostic(
                        code="tool_name_conflict",
                        field=name,
                        message="Distinct functions share this tool name; calls by name "
                        "are refused.",
                    )
                )
                continue
            entry = InventoryEntry(name, config.tools.get(name), next(iter(candidates)))
            entries[name] = entry
            low, warnings = _fidelity(entry)
            diagnostics.extend(warnings)
            if low:
                low_fidelity.append(name)
        declared_not_found = tuple(name for name in config.tools if name not in found)
        diagnostics.extend(tool_not_found(name) for name in declared_not_found)
        undeclared = tuple(name for name in entries if name not in config.tools)
        return cls(
            config=config,
            entries=entries,
            declared_not_found=declared_not_found,
            registered_undeclared=undeclared,
            ambiguous=tuple(ambiguous),
            low_fidelity=tuple(low_fidelity),
            diagnostics=tuple(diagnostics),
        )

    def summary(self) -> ToolSummary:
        return ToolSummary(
            real=tuple(name for name, entry in self.entries.items() if not entry.dry_run),
            dry_run=tuple(name for name, entry in self.entries.items() if entry.dry_run),
            low_fidelity=self.low_fidelity,
            warnings=tuple(item for item in self.diagnostics if item.severity == "warning"),
        )

    def describe(self) -> dict[str, Any]:
        """Every declared or registered tool as plain JSON data, without any of its objects."""
        names = sorted(set(self.config.tools) | set(self.entries) | set(self.ambiguous))
        tools: list[dict[str, Any]] = []
        for name in names:
            declaration = self.config.tools.get(name)
            entry = self.entries.get(name)
            described: dict[str, Any] = {
                "name": name,
                "registered": entry is not None or name in self.ambiguous,
                "safe": declaration is not None and declaration.safe,
                "classified": declaration is not None
                and declaration.classification is not ToolClass.UNCLASSIFIED,
                "ambiguous": name in self.ambiguous,
                "signature_available": False,
                "supports_sync": entry is not None and entry.registered.proxy is not None,
                "supports_async": entry is not None and entry.registered.async_proxy is not None,
                "diagnostics": [item.code for item in self.diagnostics if item.field == name],
            }
            if entry is not None and entry.registered.originals:
                described.update(_signature_description(entry.registered.originals[0]))
            tools.append(described)
        return {"complete": True, "tools": tools}

    def _released(self, name: str, session: AnySession) -> InventoryEntry:
        if name in self.ambiguous:
            raise InvocationRefused("tool_name_conflict")
        entry = self.entries.get(name)
        if entry is None:
            raise InvocationRefused("tool_not_found")
        policy = session.tools.get(name)
        if entry.dry_run or policy is None or policy.dry_run:
            raise NotSafeToCall
        return entry

    def _call(
        self,
        entry: InventoryEntry,
        actor: SessionActor | None,
        arguments: Mapping[str, Any],
        session: AnySession,
        directory: Path,
    ) -> Any:
        acting = session.model_copy(update={"actor": actor})
        with activate(acting, directory):
            if entry.registered.proxy is not None:
                return entry.registered.proxy(**arguments)
            if entry.registered.async_proxy is not None:
                return asyncio.run(entry.registered.async_proxy(**arguments))
        raise InvocationRefused("tool_not_found")

    def invoke_as(
        self,
        name: str,
        identity: Role,
        arguments: Mapping[str, Any],
        *,
        session: AnySession,
        directory: Path,
    ) -> Any:
        """Calls a released tool as the attacker or the victim of the fixtures."""
        entry = self._released(name, session)
        fixture = getattr(self.config.fixtures, identity)
        if fixture is None:
            raise InvocationRefused("missing_identity")
        actor = SessionActor(id=fixture.id, role=identity)
        return self._call(entry, actor, arguments, session, directory)

    def invoke_without_actor(
        self,
        name: str,
        arguments: Mapping[str, Any],
        *,
        session: AnySession,
        directory: Path,
    ) -> Any:
        """Calls a released tool with no actor, for attacks that leave the identity out.

        The same checks as ``invoke_as`` apply, and the call still goes through the proxy, which
        records it; only the actor and its argument are left out on purpose.
        """
        entry = self._released(name, session)
        return self._call(entry, None, arguments, session, directory)


_PARAMETER_KINDS: dict[object, str] = {
    inspect.Parameter.POSITIONAL_ONLY: "positional_only",
    inspect.Parameter.POSITIONAL_OR_KEYWORD: "positional_or_keyword",
    inspect.Parameter.VAR_POSITIONAL: "var_positional",
    inspect.Parameter.KEYWORD_ONLY: "keyword_only",
    inspect.Parameter.VAR_KEYWORD: "var_keyword",
}
_VARIADIC = (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)


def _signature_description(original: Callable[..., Any]) -> dict[str, Any]:
    """Names, kinds and default presence only: defaults and annotations are the target's data."""
    try:
        signature = inspect.signature(original)
    except (TypeError, ValueError):
        return {"signature_available": False}
    parameters = list(signature.parameters.values())
    return {
        "signature_available": True,
        "parameters": [
            {
                "name": item.name,
                "kind": _PARAMETER_KINDS[item.kind],
                "has_default": item.default is not inspect.Parameter.empty,
            }
            for item in parameters
        ],
        "required_arguments": [
            item.name
            for item in parameters
            if item.default is inspect.Parameter.empty and item.kind not in _VARIADIC
        ],
    }


def _fidelity(entry: InventoryEntry) -> tuple[bool, list[Diagnostic]]:
    declaration = entry.declaration
    if declaration is None:
        return True, [
            Diagnostic(
                code="tool_undeclared",
                severity="warning",
                field=entry.name,
                message="This tool is not declared in gazua.yaml; it stays in dry-run.",
            )
        ]
    if not declaration.requires_dry_run:
        return False, []
    if not declaration.has_dry_run_return:
        return True, [
            Diagnostic(
                code="dry_run_generic",
                severity="warning",
                field=entry.name,
                message="No dry_run_return; this tool returns a generic ok and dependent "
                "attacks are low fidelity.",
            )
        ]
    originals = entry.registered.originals
    if any(check_fidelity(item, declaration.dry_run_return) is False for item in originals):
        return True, [
            Diagnostic(
                code="dry_run_fidelity",
                severity="warning",
                message=f"dry_run_return of tool {entry.name} does not match its declared "
                "return type.",
            )
        ]
    return False, []
