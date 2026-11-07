"""Configuration contract shared by the features that consume ``gazua.yaml``."""

from gazua.config.absences import Absence, AbsenceResult, find_absences, tool_not_found
from gazua.config.diagnostics import ConfigError, Diagnostic
from gazua.config.loader import LoadedConfig, SourceMap, load_config, load_config_text
from gazua.config.models import (
    FixtureRecord,
    Fixtures,
    Gate,
    GazuaConfig,
    Identity,
    LegitTask,
    Limits,
    MoldSources,
    Target,
    Tool,
    ToolClass,
)
from gazua.config.references import resolve_reference

__all__ = [
    "Absence",
    "AbsenceResult",
    "ConfigError",
    "Diagnostic",
    "FixtureRecord",
    "Fixtures",
    "Gate",
    "GazuaConfig",
    "Identity",
    "LegitTask",
    "Limits",
    "LoadedConfig",
    "MoldSources",
    "SourceMap",
    "Target",
    "Tool",
    "ToolClass",
    "find_absences",
    "load_config",
    "load_config_text",
    "resolve_reference",
    "tool_not_found",
]
