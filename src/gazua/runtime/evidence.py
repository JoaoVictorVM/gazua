"""Evidence of each execution: raw data kept private for verdicts, redacted copies that persist.

Raw call logs, receiver bodies and outputs can carry canaries and test data, so they live in a
private folder of the run, readable only by the user running Gazua, until the verdict consumer
has seen them. What persists is redacted by declared canaries and known secret and contact
patterns. Nothing here walks the environment to find secrets. A private folder left by an
abrupt stop is marked and removed the next time a run starts under the same root.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from gazua.diagnostics import REDACTED, SECRET_PATTERNS
from gazua.runtime.processes import Capture
from gazua.runtime.receiver import CapturedHit
from gazua.runtime.session_models import CallRecord

PRIVATE_FOLDER = "private"
PRIVATE_MARKER = "GAZUA-PRIVATE"
REDACTED_CANARY = "[redacted-canary]"
REDACTED_EMAIL = "[redacted-email]"
TRUNCATION_MARK = "\n[output truncated by Gazua]\n"
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


class EvidencePathError(Exception):
    """A run folder is a link or escapes the project. Nothing is written there."""


class Redactor:
    """Removes declared canaries, key-shaped text and email addresses from persisted data."""

    def __init__(self, canaries: Iterable[str]) -> None:
        self._canaries = sorted({item for item in canaries if item}, key=len, reverse=True)

    def text(self, value: str) -> str:
        for canary in self._canaries:
            value = value.replace(canary, REDACTED_CANARY)
        value = SECRET_PATTERNS.sub(REDACTED, value)
        return _EMAIL.sub(REDACTED_EMAIL, value)

    def data(self, value: object) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.data(item) for item in cast("list[object]", value)]
        if isinstance(value, dict):
            items = cast("dict[object, object]", value)
            return {self.text(str(key)): self.data(item) for key, item in items.items()}
        return value

    def capture(self, capture: Capture) -> str:
        text = self.text(capture.data.decode("utf-8", errors="replace"))
        return text + TRUNCATION_MARK if capture.truncated else text


@dataclass(frozen=True, slots=True)
class PrivateEvidence:
    """Everything a verdict needs about one execution, before redaction.

    ``complete`` is False when anything may be missing, so an absence here never proves that
    the attack had no effect.
    """

    execution_id: str
    calls: tuple[CallRecord, ...]
    truncated_tail: bool
    receiver_hits: tuple[CapturedHit, ...]
    output: Any
    stdout: Capture
    stderr: Capture
    complete: bool


@dataclass(frozen=True, slots=True)
class PublicReferences:
    call_log: str | None
    receiver_hits: str | None
    output: str | None


def _refuse_link(path: Path) -> None:
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise EvidencePathError(str(path))


def safe_directory(root: Path, *parts: str, private: bool = False) -> Path:
    """Creates ``root/parts`` one level at a time, refusing links and names that escape."""
    path = root
    for part in parts:
        if not part or part in (".", "..") or "/" in part or "\\" in part or ":" in part:
            raise EvidencePathError(part)
        path = path / part
        _refuse_link(path)
        path.mkdir(mode=0o700 if private else 0o777, exist_ok=True)
    if private and os.name == "posix":
        path.chmod(stat.S_IRWXU)
    return path


def write_atomic(path: Path, content: str) -> None:
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _dumps(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=False)


def remove_stale_private(runs_root: Path) -> int:
    """Removes private folders that an abrupt stop left in earlier runs under this root."""
    removed = 0
    if not runs_root.is_dir() or runs_root.is_symlink():
        return removed
    for run in runs_root.iterdir():
        folder = run / "engine" / PRIVATE_FOLDER
        if run.is_symlink() or folder.is_symlink() or not (folder / PRIVATE_MARKER).is_file():
            continue
        shutil.rmtree(folder, ignore_errors=True)
        removed += 1
    return removed


class EvidenceStore:
    """The evidence folders of one run under ``engine_root``."""

    def __init__(self, project_root: Path, engine_root: Path, redactor: Redactor) -> None:
        relative = engine_root.relative_to(project_root)
        self.project_root = project_root
        self.engine_root = engine_root
        self.redactor = redactor
        self._parts = relative.parts

    @property
    def private_root(self) -> Path:
        return self.engine_root / PRIVATE_FOLDER

    def open(self) -> None:
        safe_directory(self.project_root, *self._parts)
        safe_directory(self.engine_root, PRIVATE_FOLDER, private=True)
        (self.private_root / PRIVATE_MARKER).write_text(
            "Private evidence of an unfinished Gazua run. Removed by the next run.\n",
            encoding="utf-8",
        )
        safe_directory(self.engine_root, "executions")

    def working_directory(self, execution_id: str) -> Path:
        """Where the worker writes its session, call log, events and result."""
        return safe_directory(self.private_root, execution_id, private=True)

    def public_directory(self, execution_id: str) -> Path:
        return safe_directory(self.engine_root, "executions", execution_id)

    def reference(self, execution_id: str, name: str) -> str:
        return f"executions/{execution_id}/{name}"

    def persist(self, evidence: PrivateEvidence, raw_call_log: Sequence[str]) -> PublicReferences:
        """Writes the redacted views of one execution and returns where they are."""
        folder = self.public_directory(evidence.execution_id)
        identifier = evidence.execution_id
        call_log = hits = output = None
        if raw_call_log:
            lines = [_dumps(self.redactor.data(json.loads(line))) for line in raw_call_log]
            write_atomic(folder / "calls.redacted.jsonl", "".join(f"{line}\n" for line in lines))
            call_log = self.reference(identifier, "calls.redacted.jsonl")
        if evidence.receiver_hits:
            bodies = self.reference(identifier, "hit-bodies.redacted.jsonl")
            records = [
                item.record.model_copy(update={"evidence": bodies}).model_dump(mode="json")
                for item in evidence.receiver_hits
            ]
            write_atomic(
                folder / "hits.redacted.jsonl",
                "".join(_dumps(self.redactor.data(record)) + "\n" for record in records),
            )
            write_atomic(
                folder / "hit-bodies.redacted.jsonl",
                "".join(
                    _dumps(
                        {
                            "hit_id": item.record.hit_id,
                            "content_type": item.content_type,
                            "body": self.redactor.text(item.body.decode("utf-8", "replace")),
                        }
                    )
                    + "\n"
                    for item in evidence.receiver_hits
                ),
            )
            hits = self.reference(identifier, "hits.redacted.jsonl")
        if evidence.output is not None:
            redacted = _dumps(self.redactor.data(evidence.output))
            write_atomic(folder / "output.redacted.json", redacted)
            output = self.reference(identifier, "output.redacted.json")
        for name, capture in (("stdout", evidence.stdout), ("stderr", evidence.stderr)):
            if capture.data:
                write_atomic(folder / f"{name}.redacted.txt", self.redactor.capture(capture))
        return PublicReferences(call_log, hits, output)

    def discard(self, execution_id: str) -> None:
        folder = self.private_root / execution_id
        if folder.is_dir() and not folder.is_symlink():
            shutil.rmtree(folder, ignore_errors=True)

    def close(self) -> None:
        if self.private_root.is_dir() and not self.private_root.is_symlink():
            shutil.rmtree(self.private_root, ignore_errors=True)
