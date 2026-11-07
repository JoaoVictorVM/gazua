"""Attack mold catalog: format, safe loading, selection and binding, without execution."""

from gazua.catalog.bindings import BindingContext, BindingImpediment, BoundMold, bind_mold
from gazua.catalog.loader import (
    RELEASES,
    CatalogEntry,
    CatalogLoadResult,
    LoadedMold,
    MoldDiagnostic,
    MoldError,
    load_catalog,
    load_mold_text,
)
from gazua.catalog.models import (
    DAMAGES,
    DEFAULT_SEVERITY,
    ENTRIES,
    MODES,
    REQUIREMENTS,
    TECHNIQUES,
    TOKENS,
    Mold,
    build_mold_json_schema,
)
from gazua.catalog.selection import RequirementReport, inspect_requirements, select_molds

__all__ = [
    "DAMAGES",
    "DEFAULT_SEVERITY",
    "ENTRIES",
    "MODES",
    "RELEASES",
    "REQUIREMENTS",
    "TECHNIQUES",
    "TOKENS",
    "BindingContext",
    "BindingImpediment",
    "BoundMold",
    "CatalogEntry",
    "CatalogLoadResult",
    "LoadedMold",
    "Mold",
    "MoldDiagnostic",
    "MoldError",
    "RequirementReport",
    "bind_mold",
    "build_mold_json_schema",
    "inspect_requirements",
    "load_catalog",
    "load_mold_text",
    "select_molds",
]
