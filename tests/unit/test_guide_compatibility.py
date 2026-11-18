import hashlib
import json
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest
from baseline_factory import baseline
from baseline_factory import entry as baseline_entry
from report_factory import document

from gazua.reports import fixes
from gazua.reports.legacy_guides import FALLBACK_FILE, fallback_guide
from gazua.reports.storage import document_json, parse_run_document

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_V1 = ROOT / "tests" / "support" / "run-example.json"
EXAMPLE_V2 = ROOT / "tests" / "support" / "run-example-v2.json"
# Canonical digest of the first editorial revision; a change here is a new revision, not an edit.
FROZEN_DIGEST = "fe43c6ae3a017de1e3b845593a8c8e0d0dc3d1b8c1de4f9a4d83d1afcb46a30d"


def _changed_catalog(monkeypatch: pytest.MonkeyPatch) -> None:
    edited = {
        language: {
            damage: (["Changed cause."], ["Changed risk."], ["Changed."], "Changed control.")
            for damage in by_damage
        }
        for language, by_damage in fixes._EDITORIAL.items()  # type: ignore[attr-defined]
    }
    monkeypatch.setattr(fixes, "_EDITORIAL", edited)
    monkeypatch.setattr(fixes, "GUIDE_REVISION", 9)


def test_v1_adaptation_marks_fallback() -> None:
    content = EXAMPLE_V1.read_bytes()
    original = json.loads(content)

    adapted = parse_run_document(content)

    assert adapted.guide.origin == "legacy_fallback"
    assert adapted.guide.revision == 1
    assert adapted.guide.language == original["metadata"]["language"]
    assert adapted.guide == fallback_guide(original["metadata"]["language"])
    assert [item.id for item in adapted.findings] == [item["id"] for item in original["findings"]]
    assert adapted.model_dump(mode="json")["fixes"] == original["fixes"]
    assert EXAMPLE_V1.read_bytes() == content


def test_v2_adaptation_preserves_baseline_and_verification() -> None:
    content = EXAMPLE_V2.read_bytes()
    original = json.loads(content)

    adapted = parse_run_document(content)
    data = adapted.model_dump(mode="json")

    assert original["schema_version"] == 2
    assert adapted.schema_version == 4
    assert adapted.guide.origin == "legacy_fallback"
    assert original["baseline"] is not None
    for name in ("baseline", "verification", "findings", "scenarios", "proofs", "fixes"):
        assert data[name] == original[name], name
    assert adapted.report_exit_code == original["report_exit_code"]
    assert EXAMPLE_V2.read_bytes() == content

    built = document()
    [finding] = built.findings
    compared = json.loads(document_json(document(baseline=baseline(baseline_entry(finding.id)))))
    compared.pop("guide")
    compared.pop("target_adapter")
    compared.pop("mcp")
    compared["schema_version"] = 2
    again = parse_run_document(json.dumps(compared).encode())
    assert again.model_dump(mode="json")["baseline"] == compared["baseline"]
    assert again.guide.origin == "legacy_fallback"


def test_v3_uses_captured_guide_after_catalog_change(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = document()
    content = document_json(captured).encode()
    data: dict[str, Any] = json.loads(content)
    data["guide"]["revision"] = 7
    data["guide"]["entries"]["idor_via_agent"]["fixes_cause"] = ["An older revision's text."]
    older = json.dumps(data).encode()

    _changed_catalog(monkeypatch)

    assert fixes.guide_for("en").revision == 9
    assert parse_run_document(content).guide == captured.guide
    kept = parse_run_document(older).guide
    assert kept.revision == 7
    assert kept.origin == "captured"
    assert kept.entry("idor_via_agent").fixes_cause == ["An older revision's text."]


def test_legacy_fallback_is_frozen(monkeypatch: pytest.MonkeyPatch) -> None:
    data = json.loads(files("gazua").joinpath(FALLBACK_FILE).read_text(encoding="utf-8"))
    canonical = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))

    assert hashlib.sha256(canonical.encode()).hexdigest() == FROZEN_DIGEST
    before = {language: fallback_guide(language) for language in ("en", "pt")}
    _changed_catalog(monkeypatch)
    assert {language: fallback_guide(language) for language in ("en", "pt")} == before
    adapted = parse_run_document(EXAMPLE_V1.read_bytes())
    assert adapted.guide == before[adapted.metadata.language]
