"""Baseline documents and entries with readable defaults, built through the real models."""

from __future__ import annotations

from typing import Any

from gazua.baseline.models import BaselineDocument, BaselineEntry, baseline_json

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
FINDING_A = "finding-" + "1" * 64
FINDING_B = "finding-" + "2" * 64
FINDING_C = "finding-" + "3" * 64
RUN_ID = "GAZUA-run-verify-1"
VERIFIED_AT = "2026-01-02T00:00:00.000000Z"


def reference(digest: str = DIGEST_A, language: str = "en") -> dict[str, Any]:
    return {"scenario_digest": digest, "language": language}


def entry(
    identifier: str = FINDING_A,
    *,
    status: str = "open",
    mode: str = "tools",
    scenarios: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    chosen = scenarios if scenarios is not None else [reference()]
    receipt = (
        {
            "run_id": RUN_ID,
            "verified_at": VERIFIED_AT,
            "repetitions": 20,
            "scenarios": chosen,
        }
        if status == "closed"
        else None
    )
    return {
        "id": identifier,
        "mode": mode,
        "status": status,
        "scenarios": chosen,
        "verification": receipt,
    }


def document_data(*entries: dict[str, Any], revision: int = 1) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "gazua_version": "0.1.0.dev0",
        "revision": revision,
        "entries": sorted(entries, key=lambda item: item["id"]),
    }


def baseline(*entries: dict[str, Any], revision: int = 1) -> BaselineDocument:
    return BaselineDocument.model_validate(document_data(*entries, revision=revision))


def baseline_entry(**fields: Any) -> BaselineEntry:
    return BaselineEntry.model_validate(entry(**fields))


def baseline_bytes(*entries: dict[str, Any], revision: int = 1) -> bytes:
    return baseline_json(baseline(*entries, revision=revision)).encode("utf-8")
