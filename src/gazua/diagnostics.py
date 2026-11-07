"""Structured errors and warnings that never carry the values they describe."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

REDACTED = "[redacted]"

SECRET_PATTERNS = re.compile(
    r"""
    -----BEGIN[ A-Z0-9]*PRIVATE\ KEY-----
    | \bsk-[A-Za-z0-9_-]{20,}
    | \b[sr]k_live_[A-Za-z0-9]{16,}
    | \b(?:AKIA|ASIA)[0-9A-Z]{16}\b
    | \bgh[pousr]_[A-Za-z0-9]{36,}
    | \bgithub_pat_[A-Za-z0-9_]{22,}
    | \bglpat-[A-Za-z0-9_-]{20,}
    | \bxox[abeoprs]-[A-Za-z0-9-]{10,}
    | \bAIza[0-9A-Za-z_-]{35}
    | \bnpm_[A-Za-z0-9]{36}
    | \bpypi-AgE[A-Za-z0-9_-]{16,}
    """,
    re.VERBOSE,
)


def looks_like_secret(text: str) -> bool:
    return SECRET_PATTERNS.search(text) is not None


def sanitize(text: str) -> str:
    """Prepares names and paths for printing: no control characters, no key-shaped text."""
    redacted = SECRET_PATTERNS.sub(REDACTED, text)
    return "".join(char if char.isprintable() else "?" for char in redacted)


@dataclass(frozen=True, slots=True)
class Diagnostic:
    code: str
    message: str
    file: str | None = None
    line: int | None = None
    column: int | None = None
    field: str | None = None
    severity: Literal["error", "warning"] = "error"

    def render(self) -> str:
        location = [sanitize(self.file)] if self.file else []
        if self.line is not None and self.column is not None:
            location += [str(self.line), str(self.column)]
        prefix = ":".join(location)
        parts = [prefix] if prefix else []
        if self.field:
            parts.append(sanitize(self.field))
        parts.append(sanitize(self.message))
        return ": ".join(parts)


class ConfigError(Exception):
    """One or more diagnostics that stop the operation."""

    def __init__(self, diagnostics: Iterable[Diagnostic]) -> None:
        self.diagnostics = tuple(diagnostics)
        super().__init__("\n".join(item.render() for item in self.diagnostics))
