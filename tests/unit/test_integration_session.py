import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from gazua.integration.session import (
    MAX_SESSION_BYTES,
    SESSION_ENV,
    InvalidSession,
    Session,
    activated,
    decide,
    parse_session,
    session_state,
)

StartSession = Callable[..., Path]
Policy = Callable[..., dict[str, Any]]


def test_without_the_environment_variable_there_is_no_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(SESSION_ENV, raising=False)

    assert session_state() is None


def test_valid_session_is_read_with_call_log_beside_it(
    start_session: StartSession, policy: Policy
) -> None:
    log = start_session(
        actor={"id": "attacker-1", "role": "attacker"},
        tools={"refund": policy(dry_run=False, actor_arg="user_id")},
        injections=[{"id": "i1", "tool": "search", "text": "x", "max_deliveries": 2}],
    )

    state = session_state()

    assert isinstance(state, Session)
    assert state.call_log == log
    assert state.actor is not None
    assert state.actor.role == "attacker"
    assert state.tools["refund"].actor_arg == "user_id"
    assert state.injections[0].max_deliveries == 2


def write_raw(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content: bytes) -> Path:
    path = tmp_path / "session.json"
    path.write_bytes(content)
    monkeypatch.setenv(SESSION_ENV, str(path))
    return path


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        pytest.param(b"{not json", "session_malformed", id="malformed"),
        pytest.param(b'{"schema_version": NaN}', "session_malformed", id="nan"),
        pytest.param(b"[]", "session_invalid", id="not-an-object"),
        pytest.param(b'{"schema_version": 2}', "session_version", id="unknown-version"),
        pytest.param(b'{"schema_version": true}', "session_version", id="boolean-version"),
        pytest.param(b"\xff\xfe", "session_malformed", id="not-utf8"),
    ],
)
def test_unreadable_session_documents_are_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content: bytes, reason: str
) -> None:
    write_raw(tmp_path, monkeypatch, content)

    assert session_state() == InvalidSession(reason)


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"mode": "both"}, id="mode"),
        pytest.param({"run_id": ""}, id="empty-run-id"),
        pytest.param({"extra": 1}, id="extra-field"),
        pytest.param({"tools": {"t": {"dry_run": "no"}}}, id="tool-shape"),
        pytest.param({"actor": {"id": "a", "role": "admin"}}, id="role"),
        pytest.param(
            {"injections": [{"id": "i", "tool": "t", "text": "", "max_deliveries": 0}]},
            id="deliveries",
        ),
    ],
)
def test_sessions_with_invalid_fields_are_invalid(
    start_session: StartSession, overrides: dict[str, Any]
) -> None:
    start_session(**overrides)

    assert session_state() == InvalidSession("session_invalid")


def test_missing_too_large_and_non_regular_sessions_are_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(SESSION_ENV, str(tmp_path / "absent.json"))
    assert session_state() == InvalidSession("session_unreadable")

    monkeypatch.setenv(SESSION_ENV, "")
    assert session_state() == InvalidSession("session_unreadable")

    monkeypatch.setenv(SESSION_ENV, str(tmp_path))
    assert session_state() == InvalidSession("session_not_regular")

    write_raw(tmp_path, monkeypatch, b" " * (MAX_SESSION_BYTES + 1))
    assert session_state() == InvalidSession("session_too_large")


def test_rewritten_session_file_is_read_again(start_session: StartSession) -> None:
    start_session(run_id="first")
    first = session_state()
    start_session(run_id="second-run")

    second = session_state()

    assert isinstance(first, Session)
    assert isinstance(second, Session)
    assert (first.run_id, second.run_id) == ("first", "second-run")


def test_activated_session_takes_precedence_and_is_removed_after(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(SESSION_ENV, raising=False)
    session = parse_session(
        {
            "schema_version": 1,
            "run_id": "in-process",
            "mode": "tools",
            "call_log": "log.jsonl",
            "actor": None,
            "as_user": None,
            "tools": {},
            "injections": [],
        },
        tmp_path,
    )

    with activated(session):
        assert session_state() is session
    assert session_state() is None


def test_decision_for_declared_and_undeclared_tools(
    start_session: StartSession, policy: Policy
) -> None:
    start_session(
        tools={
            "safe_read": policy(dry_run=False),
            "refund": policy(has_dry_run_return=True, dry_run_return={"ok": True}),
            "delete": policy(),
        }
    )
    state = session_state()
    assert isinstance(state, Session)

    real, declared, generic, undeclared = (
        decide(state, name) for name in ("safe_read", "refund", "delete", "unknown")
    )

    assert (real.dry_run, real.low_fidelity, real.undeclared) == (False, False, False)
    assert (declared.dry_run, declared.low_fidelity) == (True, False)
    assert (generic.dry_run, generic.low_fidelity) == (True, True)
    assert (undeclared.dry_run, undeclared.low_fidelity, undeclared.undeclared) == (
        True,
        True,
        True,
    )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_session_without_read_permission_is_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write_raw(tmp_path, monkeypatch, json.dumps({"schema_version": 1}).encode())
    os.chmod(path, 0)
    if os.access(path, os.R_OK):
        pytest.skip("running with privileges that ignore file permissions")

    assert session_state() == InvalidSession("session_unreadable")
