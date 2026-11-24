"""Writes the run document JSON Schemas, current and previous, and nothing else."""

from pathlib import Path

from gazua.reports.legacy import RUN_V1_SCHEMA_FILE, render_run_v1_json_schema
from gazua.reports.legacy_v2 import RUN_V2_SCHEMA_FILE, render_run_v2_json_schema
from gazua.reports.legacy_v3 import RUN_V3_SCHEMA_FILE, render_run_v3_json_schema
from gazua.reports.legacy_v4 import RUN_V4_SCHEMA_FILE, render_run_v4_json_schema
from gazua.reports.legacy_v5 import RUN_V5_SCHEMA_FILE, render_run_v5_json_schema
from gazua.reports.models import RUN_SCHEMA_FILE, render_run_json_schema

SCHEMAS = Path(__file__).resolve().parents[2] / "src/gazua/schemas"

if __name__ == "__main__":
    SCHEMAS.mkdir(parents=True, exist_ok=True)
    for name, content in (
        (RUN_SCHEMA_FILE, render_run_json_schema()),
        (RUN_V5_SCHEMA_FILE, render_run_v5_json_schema()),
        (RUN_V4_SCHEMA_FILE, render_run_v4_json_schema()),
        (RUN_V3_SCHEMA_FILE, render_run_v3_json_schema()),
        (RUN_V2_SCHEMA_FILE, render_run_v2_json_schema()),
        (RUN_V1_SCHEMA_FILE, render_run_v1_json_schema()),
    ):
        (SCHEMAS / name).write_text(content, encoding="utf-8", newline="\n")
