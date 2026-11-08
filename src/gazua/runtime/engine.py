"""Run engine: prepares a plan for one target and runs each attempt in a supervised worker.

The supervisor never imports the target. Workers receive JSON, not pickled objects, and every
planned entry ends in exactly one terminal record, including the ones that never started.
"""

from __future__ import annotations

import secrets
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from gazua.config.models import GazuaConfig, Limits
from gazua.diagnostics import ConfigError, Diagnostic
from gazua.runtime.run_models import (
    CostSource,
    ExecutionRequest,
    LimitOverrides,
    RunPlan,
)


def _failure(code: str, message: str, field: str | None = None) -> ConfigError:
    return ConfigError([Diagnostic(code=code, field=field, message=message)])


def _new_run_id() -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    return f"GAZUA-run-{stamp}-{secrets.token_hex(3)}"


def effective_limits(config: GazuaConfig, overrides: LimitOverrides | None) -> Limits:
    """Configured limits with every override that was given in their place."""
    values = config.limits.model_dump()
    if overrides is not None:
        values.update(overrides.model_dump(exclude_none=True))
    return Limits.model_validate(values)


def cost_source(limits: Limits, requests: Sequence[ExecutionRequest]) -> CostSource:
    """The estimate governs admission when declared; reported usage counts only without it."""
    if limits.cost_per_run is not None:
        return "estimated"
    if any(request.usage_reporting for request in requests):
        return "reported"
    return "unavailable"


def prepare_run(
    config: GazuaConfig,
    requests: Sequence[ExecutionRequest],
    overrides: LimitOverrides | None = None,
    *,
    project_root: Path,
    run_id: str | None = None,
) -> RunPlan:
    """Validates one target, its references and requests, without importing anything."""
    if not isinstance(config, GazuaConfig):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise _failure("multiple_targets", "A run tests exactly one target configuration.")
    if config.entrypoint is None and any(request.mode == "agent" for request in requests):
        raise _failure("entrypoint_missing", "Agent executions need an entrypoint.", "entrypoint")
    items = tuple(requests)
    if not items:
        raise _failure("empty_plan", "A run needs at least one execution.")
    keys = [request.key for request in items]
    if len(set(keys)) != len(keys):
        raise _failure("duplicate_request", "Each execution needs a unique key.", "requests")
    limits = effective_limits(config, overrides)
    root = project_root.resolve()
    if not root.is_dir():
        raise _failure("project_root", "The project folder does not exist.")
    identifier = run_id if run_id is not None else _new_run_id()
    if not identifier.startswith("GAZUA-run-") or not identifier.replace("-", "").isalnum():
        raise _failure(
            "run_id", "Run identifiers start with GAZUA-run- and use letters, digits and hyphens."
        )
    return RunPlan(
        run_id=identifier,
        config=config,
        project_root=root,
        engine_root=root / ".gazua" / "runs" / identifier / "engine",
        requests=items,
        limits=limits,
        effective_concurrency=1 if config.target.reset is not None else limits.concurrency,
        cost_source=cost_source(limits, items),
    )
