"""Writes the public session and call record JSON Schemas from the runtime models."""

from pathlib import Path

from gazua.runtime.session_models import (
    CALL_RECORD_SCHEMA_FILE,
    SESSION_SCHEMA_FILE,
    render_call_record_json_schema,
    render_session_json_schema,
)

SCHEMAS = Path(__file__).resolve().parents[2] / "src/gazua/schemas"

if __name__ == "__main__":
    SCHEMAS.mkdir(parents=True, exist_ok=True)
    for name, content in (
        (SESSION_SCHEMA_FILE, render_session_json_schema()),
        (CALL_RECORD_SCHEMA_FILE, render_call_record_json_schema()),
    ):
        (SCHEMAS / name).write_text(content, encoding="utf-8", newline="\n")
