"""Builds the session of one execution from ``gazua.yaml`` and hands it to the target."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, overload

from gazua.config.models import GazuaConfig
from gazua.integration.session import SESSION_ENV, activated, parse_session
from gazua.runtime.session_models import (
    AnySession,
    SessionActor,
    SessionDocument,
    SessionDocumentV2,
    SessionInjection,
    SessionReceiver,
    SessionTool,
)

SESSION_FILE = "session.json"
CALL_LOG_FILE = "calls.jsonl"
EVENTS_FILE = "events.jsonl"

Role = Literal["attacker", "victim"]


@dataclass(frozen=True, slots=True)
class SessionExecution:
    """What the run engine adds to a session for one supervised execution."""

    execution_id: str
    max_tool_calls: int
    receiver: SessionReceiver | None = None
    usage_reporting: bool = False
    events_path: str = EVENTS_FILE


@overload
def build_session(
    config: GazuaConfig,
    *,
    run_id: str,
    mode: Literal["tools", "agent"],
    actor: Role | None = None,
    injections: Sequence[SessionInjection] = (),
    call_log: str = CALL_LOG_FILE,
    execution: None = None,
) -> SessionDocument: ...
@overload
def build_session(
    config: GazuaConfig,
    *,
    run_id: str,
    mode: Literal["tools", "agent"],
    actor: Role | None = None,
    injections: Sequence[SessionInjection] = (),
    call_log: str = CALL_LOG_FILE,
    execution: SessionExecution,
) -> SessionDocumentV2: ...
def build_session(
    config: GazuaConfig,
    *,
    run_id: str,
    mode: Literal["tools", "agent"],
    actor: Role | None = None,
    injections: Sequence[SessionInjection] = (),
    call_log: str = CALL_LOG_FILE,
    execution: SessionExecution | None = None,
) -> AnySession:
    """The session for one execution. Nothing from the target is imported here.

    ``dry_run`` comes from the declarations only, so a tool runs for real only when it is
    ``safe: true`` and classified. An actor without a fixture identity stays empty. Without
    ``execution`` the session is version 1; the run engine passes one and gets version 2.
    """
    identity = getattr(config.fixtures, actor) if actor is not None else None
    base = SessionDocument(
        schema_version=1,
        run_id=run_id,
        mode=mode,
        call_log=call_log,
        actor=SessionActor(id=identity.id, role=actor)
        if identity is not None and actor is not None
        else None,
        as_user=config.target.as_user,
        tools={
            name: SessionTool(
                dry_run=tool.requires_dry_run,
                actor_arg=tool.actor_arg,
                has_dry_run_return=tool.has_dry_run_return,
                dry_run_return=tool.dry_run_return,
            )
            for name, tool in config.tools.items()
        },
        injections=list(injections),
    )
    if execution is None:
        return base
    fields = base.model_dump()
    fields["schema_version"] = 2
    return SessionDocumentV2.model_validate(
        {
            **fields,
            "execution_id": execution.execution_id,
            "max_tool_calls": execution.max_tool_calls,
            "events_path": execution.events_path,
            "receiver": None if execution.receiver is None else execution.receiver.model_dump(),
            "usage_reporting": execution.usage_reporting,
        }
    )


@dataclass(frozen=True, slots=True)
class SessionFile:
    path: Path
    call_log: Path

    @property
    def environment(self) -> dict[str, str]:
        """Variables to add to the target process environment."""
        return {SESSION_ENV: str(self.path)}


def write_session(session: AnySession, directory: Path) -> SessionFile:
    """Writes the session atomically, so the target never reads half of it."""
    directory.mkdir(parents=True, exist_ok=True)
    content = json.dumps(session.model_dump(mode="json"), ensure_ascii=True, indent=2)
    handle, temporary = tempfile.mkstemp(dir=directory, prefix=".session-", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content + "\n")
        path = directory / SESSION_FILE
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    return SessionFile(path=path, call_log=directory / session.call_log)


@contextmanager
def activate(session: AnySession, directory: Path) -> Generator[Path]:
    """Puts a session in force in this process, for tools mode, and yields the call log path.

    The document goes through the same validation the target applies to a session file.
    """
    parsed = parse_session(session.model_dump(mode="json"), directory)
    with activated(parsed):
        yield parsed.call_log
