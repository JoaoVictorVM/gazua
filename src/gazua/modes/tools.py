"""Tools mode: calls the target's tools directly, with no model, and judges the effects.

The supervisor never imports the target. Discovery reads the tools in a supervised worker, the
plan is built from that description and the configuration, and each attack runs in its own
worker through the run engine, with the verdict collector reading the private evidence.
"""

from __future__ import annotations

from pathlib import Path

from gazua.config.models import GazuaConfig
from gazua.modes.tools_models import ToolsInventory


def discover_tools(
    config: GazuaConfig, project_root: Path, timeout: float | None = None
) -> ToolsInventory:
    """The tools the test module registers when imported, without calling its entrypoint.

    Raises ``ConfigError`` when the module cannot be imported within ``timeout``.
    """
    from gazua.runtime.engine import describe_tools

    document = describe_tools(config, project_root=project_root, timeout=timeout)
    return ToolsInventory.model_validate(document)
