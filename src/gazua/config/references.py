"""Syntax of Python references and the one place allowed to import them.

Parsing a configuration or running ``gazua init`` only reads references as text. Importing
one runs the target's code, so ``resolve_reference`` is called only by features that were
explicitly asked to execute the target.
"""

from __future__ import annotations

import importlib
import keyword
from collections.abc import Callable
from typing import Any, cast

from gazua.config.diagnostics import ConfigError, Diagnostic, sanitize

IDENTIFIER_PATTERN = r"[^\W\d]\w*"
DOTTED_PATTERN = rf"{IDENTIFIER_PATTERN}(?:\.{IDENTIFIER_PATTERN})*"
REFERENCE_PATTERN = rf"^{DOTTED_PATTERN}:{DOTTED_PATTERN}$"


def is_argument_name(text: str) -> bool:
    return text.isidentifier() and not keyword.iskeyword(text)


def is_dotted_name(text: str) -> bool:
    return all(is_argument_name(part) for part in text.split("."))


def is_reference(text: str) -> bool:
    module, separator, attribute = text.partition(":")
    return bool(separator) and is_dotted_name(module) and is_dotted_name(attribute)


def _failure(code: str, purpose: str, message: str) -> ConfigError:
    return ConfigError([Diagnostic(code=code, field=purpose, message=message)])


def _import_failure(module: str, purpose: str, error: BaseException) -> ConfigError:
    # Messages from arbitrary imports can quote the target's values, so only the class and
    # the name of a missing module are reported.
    reason = type(error).__name__
    missing = error.name if isinstance(error, ImportError) else None
    if missing:
        reason = f"{reason}: missing module {missing}"
    return _failure("reference_import", purpose, f"Could not import {module} ({reason}).")


def resolve_reference(reference: str, purpose: str) -> Callable[..., Any]:
    """Imports a ``module:attribute`` reference and returns the callable it names."""
    if not is_reference(reference):
        raise _failure(
            "invalid_field", purpose, "Expected a reference in the form module:attribute."
        )
    module_name, _, attribute_path = reference.partition(":")
    try:
        resolved: object = importlib.import_module(module_name)
        for attribute in attribute_path.split("."):
            resolved = getattr(resolved, attribute)
    # Importing runs third party code, which can raise anything, including SystemExit.
    except (Exception, SystemExit) as error:  # noqa: BLE001
        raise _import_failure(module_name, purpose, error) from None
    if not callable(resolved):
        raise _failure(
            "reference_not_callable",
            purpose,
            f"The reference {sanitize(reference)} does not point to a callable.",
        )
    return cast("Callable[..., Any]", resolved)
