"""Reads the call log that the wrapper writes, for the verdict engine."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from gazua.diagnostics import ConfigError, Diagnostic
from gazua.runtime.session_models import CallRecord


@dataclass(frozen=True, slots=True)
class CallLogReading:
    """Records in order. ``truncated_tail`` says a final partial line was dropped."""

    records: tuple[CallRecord, ...]
    truncated_tail: bool


def _invalid(path: Path, line: int, message: str) -> ConfigError:
    return ConfigError(
        [Diagnostic(code="invalid_call_log", file=str(path), line=line, column=1, message=message)]
    )


def _reject_constant(name: str) -> object:
    raise ValueError(name)


def read_call_log(path: Path) -> CallLogReading:
    """Validates every complete line. A missing log means no tool was called."""
    if not path.is_file():
        return CallLogReading(records=(), truncated_tail=False)
    *complete, tail = path.read_bytes().split(b"\n")
    records: list[CallRecord] = []
    for number, raw in enumerate(complete, start=1):
        try:
            record = CallRecord.model_validate(
                json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
            )
        except (ValueError, ValidationError):
            raise _invalid(path, number, "This line is not a valid call record.") from None
        if records and record.seq <= records[-1].seq:
            raise _invalid(path, number, "Call records are out of order.")
        records.append(record)
    # A process killed mid-write leaves a final line without its newline; it is never read.
    return CallLogReading(records=tuple(records), truncated_tail=bool(tail))
