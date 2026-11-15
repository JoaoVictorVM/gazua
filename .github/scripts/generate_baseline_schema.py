"""Writes the baseline JSON Schema, and nothing else."""

from pathlib import Path

from gazua.baseline.models import BASELINE_SCHEMA_FILE, render_baseline_json_schema

SCHEMAS = Path(__file__).resolve().parents[2] / "src/gazua/schemas"

if __name__ == "__main__":
    SCHEMAS.mkdir(parents=True, exist_ok=True)
    (SCHEMAS / BASELINE_SCHEMA_FILE).write_text(
        render_baseline_json_schema(), encoding="utf-8", newline="\n"
    )
