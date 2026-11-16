"""Run documents with private markers planted in every field an issue must leave out."""

from __future__ import annotations

import json
from typing import Any

from report_factory import FOUND, document, five_states

from gazua.reports.models import RunDocument
from gazua.reports.storage import document_json

ATTACK_MARK = "MARK-SCENARIO-ATTACK"
PAYLOAD_MARK = "MARK-SCENARIO-PAYLOAD"
FINDING_ATTACK_MARK = "MARK-FINDING-ATTACK"
PROOF_MARK = "MARK-PROOF-CONTENT"
LOCATOR_MARK = "MARK-PROOF-LOCATOR"
ARGV_MARK = "MARK-REPRODUCTION-ARGV"
SYNTHETIC_MARK = "MARK-SYNTHETIC-CANARY"
SECRET = "sk-live-" + "A1b2C3d4E5f6G7h8J9k0L1m2"
EMAIL = "victim.person@example.org"
PRIVATE = (
    FINDING_ATTACK_MARK,
    PROOF_MARK,
    LOCATOR_MARK,
    ARGV_MARK,
    SYNTHETIC_MARK,
)
OPT_IN = (ATTACK_MARK, PAYLOAD_MARK)


def planted_data(**changes: Any) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(document_json(document()))
    for scenario in data["scenarios"]:
        if scenario["attack_key"] == FOUND:
            scenario["attack"] = f"{ATTACK_MARK} token {SECRET} mail {EMAIL}"
            scenario["payload"] = {"note": PAYLOAD_MARK, "api_key": SECRET, "mail": EMAIL}
    finding = data["findings"][0]
    finding["attack"] = FINDING_ATTACK_MARK
    finding["reproduction"]["argv"].append(ARGV_MARK)
    proof = data["proofs"][0]
    proof["content"] = {"body": PROOF_MARK, "secret": SECRET}
    proof["locator"] = {**proof["locator"], "note": LOCATOR_MARK}
    data["synthetic_data"]["canaries"].append(SYNTHETIC_MARK)
    data.update(changes)
    return data


def planted(**changes: Any) -> RunDocument:
    return RunDocument.model_validate_json(json.dumps(planted_data(**changes)))


def two_scenarios() -> RunDocument:
    """One finding that groups two proven scenarios of the same mold and tool."""
    from verdict_factory import context

    extra = context("victim_record_access", "tools", key="tools:idor-02:again")
    return document(five_states(extra_found=[extra]))
