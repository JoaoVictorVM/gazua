"""Writes the attack result and effect observation JSON Schemas, and nothing else."""

from pathlib import Path

from gazua.verdicts.models import (
    ATTACK_RESULT_SCHEMA_FILE,
    EFFECT_OBSERVATION_SCHEMA_FILE,
    render_attack_result_json_schema,
    render_effect_observation_json_schema,
)

SCHEMAS = Path(__file__).resolve().parents[2] / "src/gazua/schemas"

if __name__ == "__main__":
    SCHEMAS.mkdir(parents=True, exist_ok=True)
    for name, content in (
        (ATTACK_RESULT_SCHEMA_FILE, render_attack_result_json_schema()),
        (EFFECT_OBSERVATION_SCHEMA_FILE, render_effect_observation_json_schema()),
    ):
        (SCHEMAS / name).write_text(content, encoding="utf-8", newline="\n")
