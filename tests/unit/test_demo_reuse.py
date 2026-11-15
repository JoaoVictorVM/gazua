"""The store, its fixtures and the script can be reused without starting a demo."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REUSE = """
import json, sys
from gazua.demo import fixtures, target
from gazua.demo.script import ScriptedModel
state = fixtures.new_state()
model = ScriptedModel(target.TOOLS, secret=fixtures.CANARY, known_records=state.orders)
answer = model.respond("Show me my order order-attacker-1.")
print(json.dumps({
    "answer": answer,
    "loaded": sorted(
        name for name in ("gazua.demo.runner", "gazua.demo.presentation", "gazua.demo.workspace",
                          "gazua.reports.execution", "webbrowser", "gazua.runtime.engine")
        if name in sys.modules
    ),
}))
"""


def test_reusing_the_store_runs_no_demo(tmp_path: Path, clean_environment: Any) -> None:
    result = subprocess.run(
        [sys.executable, "-c", REUSE],
        cwd=tmp_path,
        env=clean_environment(),
        capture_output=True,
        text=True,
        check=True,
    )

    report = json.loads(result.stdout)
    assert '"order_id": "order-attacker-1"' in report["answer"]
    assert report["loaded"] == []
    assert list(tmp_path.iterdir()) == []
