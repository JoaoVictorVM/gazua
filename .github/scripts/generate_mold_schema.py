"""Writes the public attack mold JSON Schema from the catalog models."""

from pathlib import Path

from gazua.catalog.models import render_mold_json_schema

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "src/gazua/schemas/mold-v1.schema.json"

if __name__ == "__main__":
    SCHEMA_PATH.parent.mkdir(parents=True, exist_ok=True)
    SCHEMA_PATH.write_text(render_mold_json_schema(), encoding="utf-8", newline="\n")
