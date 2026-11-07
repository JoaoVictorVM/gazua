"""Process entry shared by the console script and ``python -m gazua``.

This module stays on the standard library and Python 3.10 syntax. An unsupported
interpreter must reach the version message below instead of failing while it imports
the CLI dependencies.
"""

from __future__ import annotations

import sys

MINIMUM_PYTHON = (3, 11)
EXIT_USAGE = 2


def main() -> int:
    if sys.version_info[:2] < MINIMUM_PYTHON:
        found = ".".join(str(part) for part in sys.version_info[:3])
        print(f"Gazua requires Python 3.11 or newer; found {found}.", file=sys.stderr)
        return EXIT_USAGE

    from gazua.cli import main as cli_main

    return cli_main()
