import json
import os
from pathlib import Path

import pytest

from gazua.runtime.evidence import (
    PRIVATE_MARKER,
    EvidencePathError,
    EvidenceStore,
    PrivateEvidence,
    Redactor,
    remove_stale_private,
    safe_directory,
)
from gazua.runtime.processes import Capture

CANARY = "GAZUA-CANARY-7f3a"


def test_redactor_removes_canaries_keys_and_emails_but_keeps_structure() -> None:
    redactor = Redactor([CANARY, ""])
    data = {
        "message": f"here is {CANARY} for victim@example.com",
        "nested": [f"key sk-{'a' * 30}", 3, None],
        CANARY: True,
    }

    redacted = redactor.data(data)

    text = json.dumps(redacted)
    assert CANARY not in text
    assert "victim@example.com" not in text
    assert "sk-aaaa" not in text
    assert redacted["nested"][1:] == [3, None]
    assert redactor.capture(Capture(f"{CANARY}\n".encode(), True)).endswith(
        "[output truncated by Gazua]\n"
    )


def test_store_persists_redacted_views_and_discards_private_data(tmp_path: Path) -> None:
    engine = tmp_path / ".gazua" / "runs" / "GAZUA-run-1" / "engine"
    store = EvidenceStore(tmp_path, engine, Redactor([CANARY]))
    store.open()
    private = store.working_directory("GAZUA-exec-0001")
    (private / "calls.jsonl").write_text(json.dumps({"arguments": {"to": CANARY}}) + "\n")

    references = store.persist(
        PrivateEvidence(
            execution_id="GAZUA-exec-0001",
            calls=(),
            truncated_tail=False,
            receiver_hits=(),
            output={"text": f"leaked {CANARY}"},
            stdout=Capture(CANARY.encode(), False),
            stderr=Capture(b"", False),
            complete=True,
        ),
        [json.dumps({"arguments": {"to": CANARY}})],
    )

    assert references.call_log == "executions/GAZUA-exec-0001/calls.redacted.jsonl"
    assert references.output == "executions/GAZUA-exec-0001/output.redacted.json"
    public = engine / "executions" / "GAZUA-exec-0001"
    for path in public.iterdir():
        assert CANARY not in path.read_text(encoding="utf-8")
    assert not (public / "stderr.redacted.txt").exists()

    store.discard("GAZUA-exec-0001")
    assert not private.exists()
    assert (store.private_root / PRIVATE_MARKER).is_file()
    store.close()
    assert not store.private_root.exists()


def test_private_leftovers_of_an_abrupt_stop_are_removed_next_time(tmp_path: Path) -> None:
    runs = tmp_path / ".gazua" / "runs"
    left = runs / "GAZUA-run-old" / "engine" / "private"
    left.mkdir(parents=True)
    (left / PRIVATE_MARKER).write_text("x", encoding="utf-8")
    (left / "GAZUA-exec-0001").mkdir()
    unmarked = runs / "GAZUA-run-other" / "engine" / "private"
    unmarked.mkdir(parents=True)

    assert remove_stale_private(runs) == 1
    assert not left.exists()
    assert unmarked.exists()


@pytest.mark.skipif(os.name != "posix", reason="symbolic links need privileges on Windows")
def test_links_and_escaping_names_are_refused(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "project").mkdir()
    (tmp_path / "project" / ".gazua").symlink_to(outside)

    with pytest.raises(EvidencePathError):
        safe_directory(tmp_path / "project", ".gazua", "runs")


@pytest.mark.parametrize("name", ["..", "a/b", "a\\b", "", "C:x"])
def test_names_that_escape_are_refused(tmp_path: Path, name: str) -> None:
    with pytest.raises(EvidencePathError):
        safe_directory(tmp_path, name)
