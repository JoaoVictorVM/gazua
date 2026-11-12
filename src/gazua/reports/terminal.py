"""Terminal output that untrusted text cannot control.

Attack, target and model text may carry escape sequences. Whole sequences are removed, not just
their ESC byte, so no command stays readable as a control instruction: CSI, OSC (hyperlinks and
clipboard writes included), DCS, SOS, PM and APC strings, their 8-bit forms, other ESC sequences
and every remaining C0 and C1 control. Only line breaks and tabs survive.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Final

from gazua.diagnostics import SECRET_PATTERNS

_STRING_END: Final = r"(?:\x07|\x1b\\|\x9c|\Z)"
_SEQUENCES: Final = re.compile(
    r"(?:\x1b[\]PX^_]|[\x9d\x90\x98\x9e\x9f])[\s\S]*?"
    + _STRING_END
    + r"|(?:\x1b\[|\x9b)[0-?]*[ -/]*(?:[@-~]|\Z)"
    + r"|\x1b[ -/]*(?:[0-~]|\Z)"
)
_CONTROLS: Final = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def clean_terminal(text: str) -> str:
    """The text without escape sequences or controls, keeping line breaks and tabs."""
    text = text.replace("\r\n", "\n")
    return _CONTROLS.sub("", _SEQUENCES.sub("", text))


def safe_line(text: str) -> str:
    """One line for the terminal: no controls, no line breaks and no key-shaped text."""
    cleaned = clean_terminal(text).replace("\n", " ").replace("\t", " ")
    return SECRET_PATTERNS.sub("[redacted]", cleaned)


def safe_lines(lines: Iterable[str]) -> list[str]:
    return [clean_terminal(line) for line in lines]


def display_path(path: str) -> str:
    """A path as printed: sanitized, and relative when the caller made it so."""
    return safe_line(path)
