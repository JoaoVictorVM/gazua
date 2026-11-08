"""The session that a Gazua run hands to the tested process, and the decision per tool.

Only the standard library is used here because this module runs inside the target's process,
where Gazua's own dependencies may be missing. A session that is referenced but cannot be read
or validated blocks every tool: running a tool for real is never the fallback.
"""

from __future__ import annotations

import json
import os
import stat
import threading
from collections.abc import Generator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Literal, cast

SESSION_ENV = "GAZUA_SESSION"
SESSION_SCHEMA_VERSION = 1
EXECUTION_SESSION_VERSION = 2
MAX_SESSION_BYTES = 1024 * 1024
RECEIVER_HOST = "127.0.0.1"

Mode = Literal["tools", "agent"]
Role = Literal["attacker", "victim"]

_SESSION_KEYS = frozenset(
    {"schema_version", "run_id", "mode", "call_log", "actor", "as_user", "tools", "injections"}
)
_TOOL_KEYS = frozenset({"dry_run", "actor_arg", "has_dry_run_return", "dry_run_return"})
_ACTOR_KEYS = frozenset({"id", "role"})
_INJECTION_KEYS = frozenset({"id", "tool", "text", "max_deliveries"})
_EXECUTION_KEYS = frozenset(
    {"execution_id", "max_tool_calls", "events_path", "receiver", "usage_reporting"}
)
_RECEIVER_KEYS = frozenset({"host", "port", "token", "execution_id"})


@dataclass(frozen=True, slots=True)
class ToolPolicy:
    dry_run: bool
    actor_arg: str | None
    has_dry_run_return: bool
    dry_run_return: Any


@dataclass(frozen=True, slots=True)
class Actor:
    id: str
    role: Role


@dataclass(frozen=True, slots=True)
class Injection:
    id: str
    tool: str
    text: str
    max_deliveries: int


@dataclass(frozen=True, slots=True)
class ReceiverEndpoint:
    """Where the local receiver of this execution listens. Never taken from an attack URL."""

    host: str
    port: int
    token: str
    execution_id: str


@dataclass(frozen=True, slots=True)
class ExecutionChannel:
    """What a version 2 session adds: one supervised execution and its local channels."""

    execution_id: str
    max_tool_calls: int
    events_path: Path
    receiver: ReceiverEndpoint | None
    usage_reporting: bool


@dataclass(frozen=True, slots=True)
class Session:
    run_id: str
    mode: Mode
    call_log: Path
    actor: Actor | None
    as_user: str | None
    tools: Mapping[str, ToolPolicy]
    injections: tuple[Injection, ...]
    execution: ExecutionChannel | None = None


@dataclass(frozen=True, slots=True)
class InvalidSession:
    """A session that exists but cannot be trusted. ``reason`` is a short code."""

    reason: str


@dataclass(frozen=True, slots=True)
class Decision:
    """What one call to a tool does inside a valid session."""

    dry_run: bool
    policy: ToolPolicy | None

    @property
    def undeclared(self) -> bool:
        return self.policy is None

    @property
    def low_fidelity(self) -> bool:
        return self.dry_run and (self.policy is None or not self.policy.has_dry_run_return)


class SessionFormatError(ValueError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _object(value: object, keys: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SessionFormatError("session_invalid")
    data = cast("dict[str, Any]", value)
    if data.keys() != keys:
        raise SessionFormatError("session_invalid")
    return data


def _text(value: object, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value):
        raise SessionFormatError("session_invalid")
    return value


def _optional_text(value: object) -> str | None:
    return None if value is None else _text(value)


def _flag(value: object) -> bool:
    if not isinstance(value, bool):
        raise SessionFormatError("session_invalid")
    return value


def _tool(value: object) -> ToolPolicy:
    data = _object(value, _TOOL_KEYS)
    actor_arg = _optional_text(data["actor_arg"])
    if actor_arg is not None and not actor_arg.isidentifier():
        raise SessionFormatError("session_invalid")
    return ToolPolicy(
        dry_run=_flag(data["dry_run"]),
        actor_arg=actor_arg,
        has_dry_run_return=_flag(data["has_dry_run_return"]),
        dry_run_return=data["dry_run_return"],
    )


def _actor(value: object) -> Actor | None:
    if value is None:
        return None
    data = _object(value, _ACTOR_KEYS)
    role = data["role"]
    if role not in ("attacker", "victim"):
        raise SessionFormatError("session_invalid")
    return Actor(id=_text(data["id"]), role=role)


def _injection(value: object) -> Injection:
    data = _object(value, _INJECTION_KEYS)
    deliveries = data["max_deliveries"]
    if isinstance(deliveries, bool) or not isinstance(deliveries, int) or deliveries < 1:
        raise SessionFormatError("session_invalid")
    return Injection(
        id=_text(data["id"]),
        tool=_text(data["tool"]),
        text=_text(data["text"], empty=True),
        max_deliveries=deliveries,
    )


def _positive(value: object, maximum: int | None = None) -> int:
    if type(value) is not int or value < 1 or (maximum is not None and value > maximum):
        raise SessionFormatError("session_invalid")
    return value


def _local_file(value: object, base: Path) -> Path:
    """A path inside the session's folder, written with forward slashes and no way out."""
    text = _text(value)
    path = PurePosixPath(text)
    if "\\" in text or ":" in text or path.is_absolute() or ".." in path.parts:
        raise SessionFormatError("session_invalid")
    return base.joinpath(*path.parts)


def _receiver(value: object, execution_id: str) -> ReceiverEndpoint | None:
    if value is None:
        return None
    data = _object(value, _RECEIVER_KEYS)
    if data["host"] != RECEIVER_HOST or data["execution_id"] != execution_id:
        raise SessionFormatError("session_invalid")
    return ReceiverEndpoint(
        host=RECEIVER_HOST,
        port=_positive(data["port"], 65535),
        token=_text(data["token"]),
        execution_id=execution_id,
    )


def _execution(data: dict[str, Any], base: Path) -> ExecutionChannel:
    execution_id = _text(data["execution_id"])
    return ExecutionChannel(
        execution_id=execution_id,
        max_tool_calls=_positive(data["max_tool_calls"]),
        events_path=_local_file(data["events_path"], base),
        receiver=_receiver(data["receiver"], execution_id),
        usage_reporting=_flag(data["usage_reporting"]),
    )


def parse_session(document: object, base: Path) -> Session:
    """Validates session data. A relative ``call_log`` is read from the session's folder.

    Version 1 and version 2 have distinct key sets, so one is never read as the other, and an
    unknown version fails closed.
    """
    if not isinstance(document, dict):
        raise SessionFormatError("session_invalid")
    version = cast("dict[str, object]", document).get("schema_version")
    if type(version) is not int or version not in (
        SESSION_SCHEMA_VERSION,
        EXECUTION_SESSION_VERSION,
    ):
        raise SessionFormatError("session_version")
    keys = _SESSION_KEYS if version == SESSION_SCHEMA_VERSION else _SESSION_KEYS | _EXECUTION_KEYS
    data = _object(cast("object", document), keys)
    mode = data["mode"]
    if mode not in ("tools", "agent"):
        raise SessionFormatError("session_invalid")
    tools = data["tools"]
    injections = data["injections"]
    if not isinstance(tools, dict) or not isinstance(injections, list):
        raise SessionFormatError("session_invalid")
    policies = {
        _text(name): _tool(policy) for name, policy in cast("dict[object, object]", tools).items()
    }
    return Session(
        run_id=_text(data["run_id"]),
        mode=mode,
        call_log=base / _text(data["call_log"]),
        actor=_actor(data["actor"]),
        as_user=_optional_text(data["as_user"]),
        tools=MappingProxyType(policies),
        injections=tuple(_injection(item) for item in cast("list[object]", injections)),
        execution=_execution(data, base) if version == EXECUTION_SESSION_VERSION else None,
    )


def _reject_constant(name: str) -> object:
    raise SessionFormatError("session_malformed")


def _read_session(path: Path, status: os.stat_result) -> Session | InvalidSession:
    if not stat.S_ISREG(status.st_mode):
        return InvalidSession("session_not_regular")
    if status.st_size > MAX_SESSION_BYTES:
        return InvalidSession("session_too_large")
    try:
        with path.open("rb") as handle:
            content = handle.read(MAX_SESSION_BYTES + 1)
    except OSError:
        return InvalidSession("session_unreadable")
    if len(content) > MAX_SESSION_BYTES:
        return InvalidSession("session_too_large")
    try:
        document = json.loads(content.decode("utf-8"), parse_constant=_reject_constant)
        return parse_session(document, path.parent)
    except SessionFormatError as error:
        return InvalidSession(error.reason)
    except (ValueError, RecursionError):
        return InvalidSession("session_malformed")


_lock = threading.Lock()
_active: list[Session] = []
_cache: dict[tuple[str, int, int, int], Session | InvalidSession] = {}


def session_state() -> Session | InvalidSession | None:
    """The session in force: one activated in this process, else the one ``GAZUA_SESSION`` names.

    ``None`` means no Gazua run is in progress, so every tool is a plain function call.
    """
    with _lock:
        if _active:
            return _active[-1]
    location = os.environ.get(SESSION_ENV)
    if location is None:
        return None
    if not location:
        return InvalidSession("session_unreadable")
    path = Path(location)
    try:
        status = path.stat()
    except (OSError, ValueError):
        return InvalidSession("session_unreadable")
    key = (str(path), status.st_mtime_ns, status.st_size, status.st_ino)
    with _lock:
        cached = _cache.get(key)
    if cached is not None:
        return cached
    state = _read_session(path, status)
    with _lock:
        _cache[key] = state
    return state


def in_session() -> bool:
    return session_state() is not None


@contextmanager
def activated(session: Session) -> Generator[Session]:
    """Puts a session in force for this process, for runs that call tools in process."""
    with _lock:
        _active.append(session)
    try:
        yield session
    finally:
        with _lock:
            _active.remove(session)


def decide(session: Session, tool: str) -> Decision:
    policy = session.tools.get(tool)
    if policy is None:
        return Decision(dry_run=True, policy=None)
    return Decision(dry_run=policy.dry_run, policy=policy)
