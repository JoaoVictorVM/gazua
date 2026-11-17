"""Writes the self-test benchmark result JSON Schema, and nothing else."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from benchmarks.selftest.models import SCHEMA_FILE, render_benchmark_json_schema  # noqa: E402

if __name__ == "__main__":
    SCHEMA_FILE.parent.mkdir(parents=True, exist_ok=True)
    SCHEMA_FILE.write_text(render_benchmark_json_schema(), encoding="utf-8", newline="\n")
