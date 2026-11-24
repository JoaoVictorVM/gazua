"""Writes the runner protocol schema and copies the shared contracts into the npm package.

With ``--check`` it writes nothing and exits 1 when a file differs from what it would write.
"""

import sys
from pathlib import Path

from gazua.typescript.models import render_protocol_json_schema

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "src/gazua/schemas"
PACKAGE_SCHEMAS = ROOT / "packages/typescript/schemas"
PROTOCOL_FILE = "typescript-runner-v1.schema.json"
SHARED = ("session-v2.schema.json", "call-record-v1.schema.json", PROTOCOL_FILE)


def expected() -> dict[Path, str]:
    protocol = render_protocol_json_schema()
    files = {SCHEMAS / PROTOCOL_FILE: protocol}
    for name in SHARED:
        source = protocol if name == PROTOCOL_FILE else (SCHEMAS / name).read_text("utf-8")
        files[PACKAGE_SCHEMAS / name] = source.replace("\r\n", "\n")
    return files


def main(arguments: list[str]) -> int:
    files = expected()
    if "--check" in arguments:
        stale = [
            path
            for path, content in files.items()
            if not path.is_file() or path.read_text("utf-8").replace("\r\n", "\n") != content
        ]
        for path in stale:
            print(f"Out of date: {path.relative_to(ROOT).as_posix()}")
        return 1 if stale else 0
    PACKAGE_SCHEMAS.mkdir(parents=True, exist_ok=True)
    for path, content in files.items():
        path.write_text(content, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
