import contextlib
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import gazua
from gazua.integration.errors import GazuaBlockedError
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
        pytest.param(b'{"schema_version": 3}', "session_version", id="unknown-version"),
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


class Spy:
    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []

    def __call__(self, *args: Any) -> str:
        self.calls.append(args)
        return "real result"


def make_tool(spy: Spy, name: str = "delete_account") -> Callable[..., str]:
    def tool(account: str) -> str:
        return spy(account)

    tool.__name__ = name
    return tool


def test_no_session_is_passthrough(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv(SESSION_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    spy = Spy()
    tools = [make_tool(spy)]
    mapping = {"delete_account": tools[0]}

    assert gazua.wrap(tools) is tools
    assert gazua.wrap(mapping) is mapping
    assert gazua.tool(tools[0]) is tools[0]
    assert tools[0]("a") == "real result"
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "corrupt",
    [
        pytest.param(lambda path: path.unlink(), id="removed"),
        pytest.param(lambda path: path.write_text("{", encoding="utf-8"), id="malformed"),
        pytest.param(
            lambda path: path.write_text('{"schema_version": 9}', encoding="utf-8"),
            id="version",
        ),
        pytest.param(lambda path: path.write_bytes(b" " * (MAX_SESSION_BYTES + 1)), id="too-large"),
        pytest.param(lambda path: (path.unlink(), path.mkdir()), id="not-regular"),
    ],
)
def test_invalid_session_fails_closed(
    start_session: StartSession, policy: Policy, corrupt: Callable[[Path], object]
) -> None:
    log = start_session(tools={"delete_account": policy(dry_run=False)})
    spy = Spy()
    (proxy,) = gazua.wrap([make_tool(spy)])
    corrupt(log.parent / "session.json")

    with pytest.raises(GazuaBlockedError) as raised:
        proxy("a")

    assert raised.value.reason == "invalid_session"
    assert spy.calls == []


@pytest.mark.parametrize(
    ("declaration", "dry_run", "expected", "low_fidelity", "undeclared"),
    [
        pytest.param({"dry_run": True}, True, "ok", True, False, id="dry-run-generic"),
        pytest.param(
            {"dry_run": True, "has_dry_run_return": True, "dry_run_return": [1]},
            True,
            [1],
            False,
            False,
            id="dry-run-declared",
        ),
        pytest.param({"dry_run": False}, False, "real result", False, False, id="real"),
        pytest.param(None, True, "ok", True, True, id="undeclared"),
    ],
)
def test_decision_table(
    start_session: StartSession,
    policy: Policy,
    read_log: Callable[[Path], list[dict[str, Any]]],
    declaration: dict[str, Any] | None,
    dry_run: bool,
    expected: object,
    low_fidelity: bool,
    undeclared: bool,
) -> None:
    tools = {} if declaration is None else {"delete_account": policy(**declaration)}
    log = start_session(tools=tools)
    spy = Spy()
    (proxy,) = gazua.wrap([make_tool(spy)])

    assert proxy("a") == expected

    assert len(spy.calls) == (0 if dry_run else 1)
    record = read_log(log)[0]
    assert (record["dry_run"], record["low_fidelity"], record["undeclared"]) == (
        dry_run,
        low_fidelity,
        undeclared,
    )
    assert record["outcome"] == "returned"


session_documents = st.fixed_dictionaries(
    {
        "schema_version": st.sampled_from([1, 1, 1, 2, "1", True]),
        "run_id": st.text(max_size=5),
        "mode": st.sampled_from(["agent", "tools", "other"]),
        "call_log": st.sampled_from(["calls.jsonl", "", "missing/calls.jsonl"]),
        "actor": st.none() | st.just({"id": "attacker-1", "role": "attacker"}),
        "as_user": st.none(),
        "tools": st.fixed_dictionaries(
            {
                "delete_account": st.fixed_dictionaries(
                    {
                        "dry_run": st.just(True),
                        "actor_arg": st.none() | st.just("account"),
                        "has_dry_run_return": st.booleans(),
                        "dry_run_return": st.none() | st.integers() | st.text(max_size=3),
                    }
                )
            }
        ),
        "injections": st.just([]),
    }
)


@settings(max_examples=100, deadline=None)
@given(document=session_documents, valid_json=st.booleans())
def test_dry_run_tool_never_runs_the_original(
    tmp_path_factory: pytest.TempPathFactory, document: dict[str, Any], valid_json: bool
) -> None:
    folder = tmp_path_factory.mktemp("session")
    path = folder / "session.json"
    path.write_text(json.dumps(document) if valid_json else "{", encoding="utf-8")
    spy = Spy()
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv(SESSION_ENV, str(path))
        (proxy,) = gazua.wrap([make_tool(spy)])
        with contextlib.suppress(GazuaBlockedError, TypeError):
            proxy("a")

    assert spy.calls == []


V2_FIELDS: dict[str, Any] = {
    "execution_id": "GAZUA-exec-0001",
    "max_tool_calls": 50,
    "events_path": "events.jsonl",
    "receiver": {
        "host": "127.0.0.1",
        "port": 40123,
        "token": "local-token",
        "execution_id": "GAZUA-exec-0001",
    },
    "usage_reporting": True,
}


def test_v1_and_v2_sessions_are_distinct_and_supported(tmp_path: Path) -> None:
    from conftest import session_document
    from gazua.config.models import GazuaConfig
    from gazua.integration.session import SessionFormatError
    from gazua.runtime import SessionExecution, SessionReceiver, build_session
    from gazua.runtime.session_models import (
        SESSION_V2_SCHEMA_FILE,
        SessionDocument,
        SessionDocumentV2,
        packaged_schema,
        render_session_v2_json_schema,
    )

    v1 = parse_session(session_document(), tmp_path)
    v2 = parse_session(session_document(schema_version=2, **V2_FIELDS), tmp_path)

    assert v1.execution is None
    assert v2.execution is not None
    assert v2.execution.events_path == tmp_path / "events.jsonl"
    assert v2.execution.receiver is not None
    assert v2.execution.receiver.port == 40123

    rejected = [
        session_document(**V2_FIELDS),
        session_document(schema_version=2),
        session_document(schema_version=3, **V2_FIELDS),
        session_document(schema_version=2, **{**V2_FIELDS, "events_path": "../out.jsonl"}),
        session_document(schema_version=2, **{**V2_FIELDS, "events_path": "/var/e.jsonl"}),
        session_document(schema_version=2, **{**V2_FIELDS, "events_path": "C:/e.jsonl"}),
        session_document(schema_version=2, **{**V2_FIELDS, "events_path": "a\\e.jsonl"}),
        session_document(schema_version=2, **{**V2_FIELDS, "max_tool_calls": 0}),
        session_document(
            schema_version=2,
            **{**V2_FIELDS, "receiver": {**V2_FIELDS["receiver"], "host": "receiver.gazua.test"}},
        ),
        session_document(
            schema_version=2,
            **{**V2_FIELDS, "receiver": {**V2_FIELDS["receiver"], "execution_id": "other"}},
        ),
    ]
    for document in rejected:
        with pytest.raises(SessionFormatError):
            parse_session(document, tmp_path)

    config = GazuaConfig.model_validate({"schema_version": 1})
    plain = build_session(config, run_id="GAZUA-run-1", mode="agent")
    extended = build_session(
        config,
        run_id="GAZUA-run-1",
        mode="agent",
        execution=SessionExecution(
            execution_id="GAZUA-exec-0001",
            max_tool_calls=7,
            receiver=SessionReceiver(
                host="127.0.0.1",
                port=1,
                token="local-token",  # noqa: S106
                execution_id="GAZUA-exec-0001",
            ),
        ),
    )
    assert isinstance(plain, SessionDocument)
    assert plain.schema_version == 1
    assert isinstance(extended, SessionDocumentV2)
    assert extended.max_tool_calls == 7
    parsed = parse_session(extended.model_dump(mode="json"), tmp_path)
    assert parsed.execution is not None
    assert parsed.execution.max_tool_calls == 7
    assert packaged_schema(SESSION_V2_SCHEMA_FILE) == render_session_v2_json_schema()
