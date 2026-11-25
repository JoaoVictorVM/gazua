"""The trust boundary of the Action, checked before the project is read or the target imported.

The event, its payload, the repository and the origin of a pull request decide which mode may
run. A pull request from a fork always runs tools mode. ``pull_request_target`` is refused, and
a payload that does not say where a pull request came from is never trusted by default.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal, cast

from gazua.reports.storage import is_link

Mode = Literal["tools", "agent"]
TRUSTED_EVENTS: Final = frozenset({"pull_request", "push", "workflow_dispatch", "schedule"})
MAX_EVENT_BYTES: Final = 8 * 1024 * 1024
MAX_EVENT_DEPTH: Final = 64
SAFE_EXAMPLE: Final = (
    "https://github.com/JoaoVictorVM/gazua/blob/main/docs/examples/gazua-github-actions.yml"
)
FORK_AGENT_NOTICE: Final = (
    "This pull request comes from a fork: agent mode was requested, but only tools mode runs, "
    "with no secrets."
)
# Credentials of the Action itself: the target's process never receives them.
ACTION_CREDENTIALS: Final = frozenset(
    {
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "GAZUA_GITHUB_TOKEN",
        "ACTIONS_RUNTIME_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
    }
)
ACTION_PREFIXES: Final = ("INPUT_", "GAZUA_CI_")
_REPOSITORY: Final = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_MOLD: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PYTHON: Final = re.compile(r"^3\.[0-9]{1,2}$")


class CiError(Exception):
    """A refusal of the CI boundary. ``code`` is safe to print and nothing else is attached."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class EventContext:
    """What the event allows. ``pull_request`` is the number, only on pull request events."""

    event: str
    repository: str
    pull_request: int | None
    fork: bool
    requested_mode: Mode
    effective_mode: Mode

    @property
    def forced_tools(self) -> bool:
        return self.requested_mode != self.effective_mode


def _depth(value: Any) -> int:
    deepest = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, level = stack.pop()
        deepest = max(deepest, level)
        if isinstance(item, dict):
            stack.extend((child, level + 1) for child in cast("dict[str, Any]", item).values())
        elif isinstance(item, list):
            stack.extend((child, level + 1) for child in cast("list[Any]", item))
    return deepest


def read_payload(path_text: str | None) -> dict[str, Any]:
    """The event payload as a JSON object, bounded in size and depth."""
    if not path_text:
        raise CiError("ci_event_invalid")
    path = Path(path_text)
    try:
        if is_link(path) or not path.is_file() or path.stat().st_size > MAX_EVENT_BYTES:
            raise CiError("ci_event_invalid")
        content = path.read_bytes()
    except OSError:
        raise CiError("ci_event_invalid") from None
    try:
        data: Any = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise CiError("ci_event_invalid") from None
    if not isinstance(data, dict) or _depth(data) > MAX_EVENT_DEPTH:
        raise CiError("ci_event_invalid")
    return cast("dict[str, Any]", data)


def _text(data: Any, *keys: str) -> str | None:
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = cast("dict[str, Any]", current).get(key)
    return current if isinstance(current, str) else None


def parse_mode(text: str) -> Mode:
    if text == "tools":
        return "tools"
    if text == "agent":
        return "agent"
    raise CiError("ci_input_invalid")


def parse_bool(text: str) -> bool:
    """``true`` or ``false`` in lowercase; anything else is refused."""
    if text == "true":
        return True
    if text == "false":
        return False
    raise CiError("ci_input_invalid")


def parse_mold(text: str) -> str | None:
    if text == "":
        return None
    if not _MOLD.fullmatch(text):
        raise CiError("ci_input_invalid")
    return text


def parse_python(text: str) -> str:
    if not _PYTHON.fullmatch(text):
        raise CiError("ci_input_invalid")
    return text


def event_context(environment: Mapping[str, str], requested: Mode) -> EventContext:
    """Validates the event before anything of the project is read. Refusals raise ``CiError``."""
    event = environment.get("GITHUB_EVENT_NAME", "")
    if event == "pull_request_target":
        raise CiError("ci_pull_request_target_refused")
    if event not in TRUSTED_EVENTS:
        raise CiError("ci_event_refused")
    repository = environment.get("GITHUB_REPOSITORY", "")
    if not _REPOSITORY.fullmatch(repository):
        raise CiError("ci_event_invalid")
    payload = read_payload(environment.get("GITHUB_EVENT_PATH"))
    if _text(payload, "repository", "full_name") != repository:
        raise CiError("ci_event_invalid")
    if event != "pull_request":
        return EventContext(event, repository, None, False, requested, requested)
    pull_request: Any = payload.get("pull_request")
    number: Any = (
        cast("dict[str, Any]", pull_request).get("number")
        if isinstance(pull_request, dict)
        else None
    )
    head = _text(pull_request, "head", "repo", "full_name")
    if type(number) is not int or number < 1 or head is None or not _REPOSITORY.fullmatch(head):
        raise CiError("ci_event_invalid")
    fork = head.lower() != repository.lower()
    effective: Mode = "tools" if fork else requested
    return EventContext(event, repository, int(number), fork, requested, effective)


def target_environment(environment: Mapping[str, str]) -> dict[str, str]:
    """The job's variables without the Action's own credentials and inputs."""
    return {
        name: value
        for name, value in environment.items()
        if name.upper() not in ACTION_CREDENTIALS and not name.upper().startswith(ACTION_PREFIXES)
    }


def workspace_file(workspace: Path, text: str, *, must_exist: bool = True) -> str:
    """A path inside the workspace, relative and in POSIX form, through no link or junction.

    Absolute paths, ``..`` escapes, links anywhere on the way and anything but a regular file
    raise ``CiError("ci_path_refused")``.
    """
    if not text or "\x00" in text or "://" in text:
        raise CiError("ci_path_refused")
    candidate = Path(text)
    if candidate.is_absolute() or candidate.drive or any(part == ".." for part in candidate.parts):
        raise CiError("ci_path_refused")
    base = workspace.resolve()
    current = base
    for part in candidate.parts:
        current = current / part
        if is_link(current):
            raise CiError("ci_path_refused")
    try:
        resolved = (base / candidate).resolve()
    except OSError:
        raise CiError("ci_path_refused") from None
    if resolved != base and base not in resolved.parents:
        raise CiError("ci_path_refused")
    if must_exist and not resolved.is_file():
        raise CiError("ci_path_refused")
    if resolved.exists() and not resolved.is_file():
        raise CiError("ci_path_refused")
    return resolved.relative_to(base).as_posix()


def workspace(environment: Mapping[str, str]) -> Path:
    text = environment.get("GITHUB_WORKSPACE") or os.getcwd()
    path = Path(text)
    if not path.is_dir() or is_link(path):
        raise CiError("ci_path_refused")
    return path.resolve()
