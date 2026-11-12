"""Minimal consumers of the run document, standing in for the commands that come later."""

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from report_factory import FOUND, NOT_APPLICABLE, RESISTED, document

from gazua.catalog.models import DAMAGES
from gazua.reports.fixes import fix_anchor
from gazua.reports.models import RunDocument
from gazua.reports.rendering import render_report
from gazua.reports.storage import document_json

DEMO_CONSUMER = (
    "import json, sys\n"
    "from gazua.reports.storage import load_run_document\n"
    "from gazua.reports.rendering import render_report\n"
    "document = load_run_document(__import__('pathlib').Path(sys.argv[1]))\n"
    "html, markdown = render_report(document)\n"
    "loaded = sorted(name for name in sys.modules if name.split('.')[0] in "
    "('tools_target', 'echo_target', 'agent_target', 'openai', 'anthropic'))\n"
    "print(json.dumps({'findings': len(document.findings), 'mode': document.metadata.mode, "
    "'loaded': loaded, 'html': len(html) > 0}))\n"
)


def as_agent(built: RunDocument) -> RunDocument:
    data = built.model_dump(mode="json")
    data["metadata"]["mode"] = "agent"
    data["metadata"]["model"] = "simulated-model"
    return RunDocument.model_validate_json(json.dumps(data))


def test_demo_can_consume_document_without_target_import(tmp_path: Path) -> None:
    built = as_agent(document())
    path = tmp_path / "run.json"
    path.write_text(document_json(built), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "-c", DEMO_CONSUMER, str(path)],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    seen = json.loads(result.stdout)
    assert seen == {"findings": 1, "mode": "agent", "loaded": [], "html": True}
    html, _ = render_report(built)
    assert "simulated-model" in html


def test_verification_consumer_gets_stable_identity_and_native_scenarios() -> None:
    first, second = document(), document()
    finding = first.findings[0]

    assert [item.id for item in first.findings] == [item.id for item in second.findings]
    results = {item.attack_key: item for item in first.verdicts.results}
    for key in finding.scenarios:
        assert results[key].state == "finding"
        assert results[key].proof
    snapshots = {item.id: item for item in first.proofs}
    assert all(snapshots[item].attack_key in finding.scenarios for item in finding.proof_ids)
    assert finding.reproduction.available


def ci_projection(built: RunDocument) -> list[dict[str, Any]]:
    return [
        {
            "id": item.id,
            "severity": item.severity,
            "damage": item.damage,
            "tool": item.tool_name,
            "reproduction": item.reproduction.argv if item.reproduction.available else None,
        }
        for item in built.findings
    ]


def test_ci_projection_needs_no_attack_text() -> None:
    built = document()

    projected = ci_projection(built)

    assert projected[0]["damage"] == "idor_via_agent"
    text = json.dumps(projected)
    assert built.findings[0].attack not in text
    assert "Direct access" not in text


def test_fix_references_resolve_for_every_damage() -> None:
    built = document()
    html, markdown = render_report(built)

    assert set(built.fixes) == set(DAMAGES)
    for damage in DAMAGES:
        assert f'id="{fix_anchor(damage)}"' in html
        assert f'<a id="{fix_anchor(damage)}"></a>' in markdown
    issue = {
        "title": f"{built.findings[0].severity}: {built.findings[0].damage}",
        "fix": built.fixes[built.findings[0].fix_ref],
        "finding": built.findings[0].id,
    }
    assert issue["fix"] == built.findings[0].fix


def test_benchmark_consumer_observes_proved_and_not_applicable_scenarios() -> None:
    built = document()
    states = {item.attack_key: item.state for item in built.verdicts.results}

    assert states[FOUND] == "finding"
    assert states[RESISTED] == "resisted"
    assert states[NOT_APPLICABLE] == "not_applicable"
