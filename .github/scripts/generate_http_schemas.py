"""Writes the JSON Schemas of the HTTP authorization receipt and the private trace evidence."""

from pathlib import Path

from gazua.http.models import RECEIPT_SCHEMA_FILE, render_receipt_json_schema
from gazua.otel.models import TRACE_SCHEMA_FILE, render_trace_json_schema

SCHEMAS = Path(__file__).resolve().parents[2] / "src/gazua/schemas"

if __name__ == "__main__":
    SCHEMAS.mkdir(parents=True, exist_ok=True)
    for name, content in (
        (RECEIPT_SCHEMA_FILE, render_receipt_json_schema()),
        (TRACE_SCHEMA_FILE, render_trace_json_schema()),
    ):
        (SCHEMAS / name).write_text(content, encoding="utf-8", newline="\n")
