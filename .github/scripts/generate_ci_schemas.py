"""Writes the CI summary, pull request comment and SARIF profile JSON Schemas, and nothing else.

With ``--check`` it writes nothing and exits 1 when a published schema differs.
"""

import sys
from pathlib import Path

from gazua.ci.models import (
    CI_SUMMARY_SCHEMA_FILE,
    PR_COMMENT_SCHEMA_FILE,
    SARIF_PROFILE_SCHEMA_FILE,
    build_ci_summary_schema,
    build_pr_comment_schema,
    render_schema,
)
from gazua.ci.sarif import build_sarif_profile_schema

SCHEMAS = Path(__file__).resolve().parents[2] / "src/gazua/schemas"


def rendered() -> dict[str, str]:
    return {
        CI_SUMMARY_SCHEMA_FILE: render_schema(build_ci_summary_schema()),
        PR_COMMENT_SCHEMA_FILE: render_schema(build_pr_comment_schema()),
        SARIF_PROFILE_SCHEMA_FILE: render_schema(build_sarif_profile_schema()),
    }


if __name__ == "__main__":
    if "--check" in sys.argv[1:]:
        stale = [
            name
            for name, content in rendered().items()
            if not (SCHEMAS / name).is_file()
            or (SCHEMAS / name).read_text(encoding="utf-8").replace("\r\n", "\n") != content
        ]
        for name in stale:
            print(f"{name} is out of date; run this script without --check.")
        sys.exit(1 if stale else 0)
    SCHEMAS.mkdir(parents=True, exist_ok=True)
    for name, content in rendered().items():
        (SCHEMAS / name).write_text(content, encoding="utf-8", newline="\n")
