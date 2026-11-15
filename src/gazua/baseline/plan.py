"""Builds a verification: 20 slots for each scenario and language of one finding, one budget.

The scenarios are the ones the baseline accepted plus the ones the current configuration
builds for the same mode, mold and tool. Every accepted scenario must still be buildable and
executable; otherwise the coverage changed and nothing runs. Each language keeps its own
scenarios under an operational key, so rates of different languages are never merged. Only
the chosen finding's scenarios are planned; agent mode's legitimate tasks are left out.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from decimal import Decimal

from gazua.baseline.models import (
    LANGUAGE_SUFFIX,
    VERIFY_REPETITIONS,
    ScenarioReference,
    scenario_digest,
)
from gazua.baseline.selection import Selection, VerifyError, target_ref
from gazua.catalog.models import Language
from gazua.config.models import GazuaConfig, Limits
from gazua.modes.tools_models import ToolsInventory
from gazua.runtime.run_models import ExecutionRequest
from gazua.verdicts.models import AttackContext

LANGUAGE_ORDER: tuple[Language, ...] = ("en", "pt")


@dataclass(frozen=True, slots=True)
class PlannedSample:
    """One scenario in one language with its 20 requests."""

    context: AttackContext
    reference: ScenarioReference
    requests: tuple[ExecutionRequest, ...]


@dataclass(frozen=True, slots=True)
class VerificationPlan:
    """Every sample of the verification and the order the engine receives them in."""

    selection: Selection
    samples: tuple[PlannedSample, ...]
    languages: tuple[Language, ...]

    @property
    def contexts(self) -> list[AttackContext]:
        return [item.context for item in self.samples]

    @property
    def references(self) -> dict[str, ScenarioReference]:
        return {item.context.attack_key: item.reference for item in self.samples}

    @property
    def requests(self) -> list[ExecutionRequest]:
        """Round by round: each sample's first repetition before any second one."""
        ordered: list[ExecutionRequest] = []
        for repetition in range(VERIFY_REPETITIONS):
            ordered.extend(item.requests[repetition] for item in self.samples)
        return ordered


def _planned(
    selection: Selection,
    config: GazuaConfig,
    inventory: ToolsInventory,
    language: Language,
) -> list[tuple[AttackContext, tuple[ExecutionRequest, ...]]]:
    suffix = f"{LANGUAGE_SUFFIX}{language}"
    if selection.mode == "tools":
        from gazua.modes.tools_plan import plan_tools

        plan = plan_tools(
            [selection.mold],
            config,
            inventory,
            language=language,
            repetitions=VERIFY_REPETITIONS,
            key_suffix=suffix,
        )
        by_key: dict[str, list[ExecutionRequest]] = {}
        for attack in plan.attacks:
            by_key[attack.context.attack_key] = list(attack.requests)
        return [(item.context, tuple(by_key[item.context.attack_key])) for item in plan.attacks]
    from gazua.modes.agent_plan import plan_agent

    agent = plan_agent(
        [selection.mold],
        config,
        inventory,
        language=language,
        repetitions=VERIFY_REPETITIONS,
        key_suffix=suffix,
        legitimate=False,
    )
    return [(item.context, item.requests) for item in agent.scenarios]


def build_plan(
    selection: Selection, config: GazuaConfig, inventory: ToolsInventory
) -> VerificationPlan:
    """The verification of the selected entry against the current target.

    Raises ``VerifyError("verification_coverage_changed")`` when an accepted scenario cannot be
    rebuilt or cannot run now; a new scenario that cannot run is left out and reported by its
    absence from the samples.
    """
    from gazua.reports.builder import finding_id

    entry = selection.entry
    recorded: set[Language] = {item.language for item in entry.scenarios}
    languages: tuple[Language, ...] = tuple(item for item in LANGUAGE_ORDER if item in recorded)
    ref = target_ref(config)
    samples: list[PlannedSample] = []
    for language in languages:
        required = {item.scenario_digest for item in entry.scenarios if item.language == language}
        built: dict[str, PlannedSample] = {}
        for context, requests in _planned(selection, config, inventory, language):
            if finding_id(ref, selection.mode, selection.mold.id, context.tool_name) != entry.id:
                continue
            original = context.attack_key.removesuffix(f"{LANGUAGE_SUFFIX}{language}")
            digest = scenario_digest(original)
            executable = len(requests) == VERIFY_REPETITIONS and context.impediment is None
            if not executable:
                if digest in required:
                    raise VerifyError("verification_coverage_changed")
                continue
            reference = ScenarioReference(scenario_digest=digest, language=language)
            built[digest] = PlannedSample(context, reference, tuple(requests))
        if not required <= set(built):
            raise VerifyError("verification_coverage_changed")
        samples.extend(built[key] for key in sorted(built))
    if not samples:
        raise VerifyError("verification_coverage_changed")
    return VerificationPlan(selection, tuple(samples), languages)


def check_budget(plan: VerificationPlan, limits: Limits) -> None:
    """Refuses before any attack when the limits cannot fit every slot. Limits never grow."""
    slots = len(plan.requests)
    if limits.max_runs < slots:
        raise VerifyError("verification_insufficient_budget")
    if limits.max_cost is not None and limits.cost_per_run is not None:
        estimate = Decimal(str(limits.cost_per_run)) * slots
        if estimate > Decimal(str(limits.max_cost)):
            raise VerifyError("verification_insufficient_budget")


def preview_lines(
    plan: VerificationPlan, limits: Limits, *, effective_concurrency: int
) -> list[str]:
    """What runs, shown before the first attempt."""
    selection = plan.selection
    slots = len(plan.requests)
    lines = [
        f"Verifying {selection.entry.id} (mold {selection.mold.id}, {selection.mode} mode, "
        f"accepted as {selection.entry.status}).",
        f"{len(plan.samples)} scenarios in {', '.join(plan.languages)}, "
        f"{VERIFY_REPETITIONS} repetitions each: {slots} executions; max_runs "
        f"{limits.max_runs}, concurrency {effective_concurrency}.",
    ]
    if limits.max_cost is not None:
        lines.append(f"Cost ceiling: {limits.max_cost} USD.")
    if selection.mode == "agent":
        lines.append(
            "Agent mode calls your agent's real model with its own configuration for every "
            "repetition."
        )
    return lines


def ordered_languages(values: Sequence[Language]) -> tuple[Language, ...]:
    return tuple(item for item in LANGUAGE_ORDER if item in values)


__all__ = [
    "PlannedSample",
    "VerificationPlan",
    "build_plan",
    "check_budget",
    "ordered_languages",
    "preview_lines",
]
