"""Writes the run document JSON Schemas, current and previous, and nothing else."""

from pathlib import Path

from gazua.reports.legacy import RUN_V1_SCHEMA_FILE, render_run_v1_json_schema
from gazua.reports.models import RUN_SCHEMA_FILE, render_run_json_schema

SCHEMAS = Path(__file__).resolve().parents[2] / "src/gazua/schemas"

if __name__ == "__main__":
    SCHEMAS.mkdir(parents=True, exist_ok=True)
    (SCHEMAS / RUN_SCHEMA_FILE).write_text(render_run_json_schema(), encoding="utf-8", newline="\n")
    (SCHEMAS / RUN_V1_SCHEMA_FILE).write_text(
        render_run_v1_json_schema(), encoding="utf-8", newline="\n"
    )
