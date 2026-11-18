"""Writes the JSON Schema of the private MCP delivery channel."""

from pathlib import Path

from gazua.mcp.models import DELIVERY_SCHEMA_FILE, render_delivery_json_schema

SCHEMAS = Path(__file__).resolve().parents[2] / "src/gazua/schemas"

if __name__ == "__main__":
    SCHEMAS.mkdir(parents=True, exist_ok=True)
    (SCHEMAS / DELIVERY_SCHEMA_FILE).write_text(
        render_delivery_json_schema(), encoding="utf-8", newline="\n"
    )
