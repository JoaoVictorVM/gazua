import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

import gazua
from gazua.config.models import GazuaConfig
from gazua.integration.errors import GazuaBlockedError
from gazua.integration.session import SESSION_ENV
from gazua.runtime import (
    InvocationRefused,
    NotSafeToCall,
    SessionDocument,
    ToolInventory,
    activate,
    build_session,
    check_fidelity,
    write_session,
)
from gazua.runtime.session_models import build_session_json_schema

ReadLog = Callable[[Path], list[dict[str, Any]]]


def config_of(**document: Any) -> GazuaConfig:
    return GazuaConfig.model_validate({"schema_version": 1, **document})


FIXTURES = {
    "attacker": {"id": "attacker-1"},
    "victim": {"id": "victim-1"},
}


class Calls:
    def __init__(self) -> None:
        self.seen: list[dict[str, Any]] = []


calls = Calls()


def read_record(record_id: int, user_id: str = "model-choice") -> dict[str, Any]:
    calls.seen.append({"record_id": record_id, "user_id": user_id})
    return {"record": record_id, "owner": user_id}


def delete_record(record_id: int) -> str:
    calls.seen.append({"deleted": record_id})
    return "deleted"


def no_actor(record_id: int) -> int:
    return record_id


@pytest.fixture(autouse=True)
def _reset_calls() -> None:
    calls.seen.clear()


def test_dry_run_flag_follows_requires_dry_run(tmp_path: Path) -> None:
    config = config_of(
        tools={
            "safe_classified": {"safe": True, "sensitive": False},
            "safe_unclassified": {"safe": True},
            "regular_not_safe": {"sensitive": False},
            "forbidden": {"forbidden": True, "dry_run_return": None},
        },
        fixtures=FIXTURES,
        target={"as_user": "auth:as_user"},
    )

    session = build_session(config, run_id="r", mode="agent", actor="victim")

    assert {name: tool.dry_run for name, tool in session.tools.items()} == {
        "safe_classified": False,
        "safe_unclassified": True,
        "regular_not_safe": True,
        "forbidden": True,
    }
    assert session.tools["forbidden"].has_dry_run_return is True
    assert session.tools["safe_classified"].has_dry_run_return is False
    assert session.actor is not None
    assert (session.actor.id, session.actor.role) == ("victim-1", "victim")
    assert session.as_user == "auth:as_user"
    assert build_session(config_of(), run_id="r", mode="tools", actor="attacker").actor is None


def test_written_session_is_valid_atomic_and_read_by_the_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, read_log: ReadLog
) -> None:
    config = config_of(tools={"delete_record": {"dry_run_return": "queued"}}, fixtures=FIXTURES)
    session = build_session(config, run_id="r1", mode="agent", actor="attacker")

    written = write_session(session, tmp_path / "run")
    monkeypatch.setenv(SESSION_ENV, written.environment[SESSION_ENV])
    (proxy,) = gazua.wrap([delete_record])

    assert proxy(1) == "queued"
    assert calls.seen == []
    assert sorted(path.name for path in written.path.parent.iterdir()) == [
        "calls.jsonl",
        "session.json",
    ]
    document = json.loads(written.path.read_text(encoding="utf-8"))
    Draft202012Validator(build_session_json_schema()).validate(document)
    assert SessionDocument.model_validate(document) == session
    assert read_log(written.call_log)[0]["tool"] == "delete_record"


def test_inventory_reconciles_declared_and_registered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = config_of(
        tools={
            "read_record": {"safe": True, "sensitive": False},
            "delete_record": {"forbidden": True, "dry_run_return": "deleted"},
            "missing_tool": {"safe": True, "sensitive": False},
        }
    )
    write = write_session(build_session(config, run_id="r", mode="tools"), tmp_path)
    monkeypatch.setenv(SESSION_ENV, str(write.path))

    def read_record_again(record_id: int) -> None: ...

    gazua.wrap([read_record, delete_record, no_actor])
    gazua.wrap({"read_record": read_record_again})
    inventory = ToolInventory.collect(config)

    assert inventory.declared_not_found == ("missing_tool",)
    assert inventory.registered_undeclared == ("no_actor",)
    assert inventory.ambiguous == ("read_record",)
    assert sorted(inventory.entries) == ["delete_record", "no_actor"]
    rendered = [item.render() for item in inventory.diagnostics]
    assert "Tool missing_tool is declared but was not discovered." in rendered
    assert any(item.code == "tool_name_conflict" for item in inventory.diagnostics)
    assert any(item.code == "tool_undeclared" for item in inventory.diagnostics)


def test_summary_counts_real_and_dry_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = config_of(
        tools={
            "read_record": {"safe": True, "sensitive": False},
            "delete_record": {"forbidden": True},
        }
    )
    write = write_session(build_session(config, run_id="r", mode="agent"), tmp_path)
    monkeypatch.setenv(SESSION_ENV, str(write.path))
    gazua.wrap([read_record, delete_record, no_actor])

    summary = ToolInventory.collect(config).summary()

    assert summary.text == "1 real tool, 2 in dry-run"
    assert summary.real == ("read_record",)
    assert summary.low_fidelity == ("delete_record", "no_actor")
    assert summary.lines()[:2] == [
        "1 real tool, 2 in dry-run",
        "Low fidelity: delete_record, no_actor",
    ]
    assert all(line.startswith("Warning: ") for line in summary.lines()[2:])
    assert ToolInventory.collect(config_of(), {}).summary().text == "0 real tools, 0 in dry-run"


def returns_text() -> str: ...
def returns_optional_list() -> list[int] | None: ...
def returns_mapping() -> dict[str, float]: ...
def returns_object() -> object: ...
def returns_nothing(): ...


@pytest.mark.parametrize(
    ("function", "value", "expected"),
    [
        pytest.param(returns_text, "ok", True, id="str"),
        pytest.param(returns_text, 1, False, id="str-mismatch"),
        pytest.param(returns_optional_list, None, True, id="optional-none"),
        pytest.param(returns_optional_list, [1, 2], True, id="list"),
        pytest.param(returns_optional_list, [True], False, id="bool-is-not-int"),
        pytest.param(returns_mapping, {"a": 1}, True, id="int-as-float"),
        pytest.param(returns_mapping, ["a"], False, id="dict-mismatch"),
        pytest.param(returns_object, "x", None, id="complex-type"),
        pytest.param(returns_nothing, "x", None, id="no-annotation"),
    ],
)
def test_fidelity_check_from_return_annotations(
    function: Callable[..., Any], value: object, expected: bool | None
) -> None:
    assert check_fidelity(function, value) is expected


def test_fidelity_warnings_from_return_annotations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = config_of(
        tools={
            "returns_text": {"dry_run_return": 5},
            "returns_mapping": {"dry_run_return": {"total": 1.5}},
            "returns_object": {"dry_run_return": "x"},
        }
    )
    write = write_session(build_session(config, run_id="r", mode="agent"), tmp_path)
    monkeypatch.setenv(SESSION_ENV, str(write.path))
    gazua.wrap([returns_text, returns_mapping, returns_object])

    inventory = ToolInventory.collect(config)

    assert inventory.low_fidelity == ("returns_text",)
    assert [item.render() for item in inventory.diagnostics if item.code == "dry_run_fidelity"] == [
        "dry_run_return of tool returns_text does not match its declared return type."
    ]


@pytest.fixture
def tools_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[..., Any]:
    """Wraps the tools under a tools mode session and returns a function that invokes them."""
    monkeypatch.delenv(SESSION_ENV, raising=False)

    def prepare(config: GazuaConfig, *functions: Callable[..., Any]) -> Callable[..., Any]:
        session = build_session(config, run_id="tools", mode="tools")
        with activate(session, tmp_path):
            gazua.wrap(list(functions))
        inventory = ToolInventory.collect(config)

        def invoke(name: str, identity: str, **arguments: Any) -> Any:
            return inventory.invoke_as(
                name, identity, arguments, session=session, directory=tmp_path
            )

        return invoke

    return prepare


def test_actor_arg_is_imposed_and_unaccepted_arg_blocks(
    tools_mode: Callable[..., Any], tmp_path: Path, read_log: ReadLog
) -> None:
    config = config_of(
        tools={
            "read_record": {"safe": True, "sensitive": False, "actor_arg": "user_id"},
            "no_actor": {"safe": True, "sensitive": False, "actor_arg": "user_id"},
        },
        fixtures=FIXTURES,
    )
    invoke = tools_mode(config, read_record, no_actor)

    assert invoke("read_record", "attacker", record_id=7, user_id="victim-1") == {
        "record": 7,
        "owner": "attacker-1",
    }
    assert invoke("read_record", "victim", record_id=8)["owner"] == "victim-1"
    with pytest.raises(GazuaBlockedError) as blocked:
        invoke("no_actor", "attacker", record_id=1)

    assert blocked.value.reason == "actor_arg_not_accepted"
    records = read_log(tmp_path / "calls.jsonl")
    assert [record["actor"] for record in records] == [
        {"id": "attacker-1", "source": "actor_arg"},
        {"id": "victim-1", "source": "actor_arg"},
        {"id": "attacker-1", "source": "actor_arg"},
    ]
    assert records[2]["outcome"] == "blocked"


@pytest.fixture
def identity_module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    package = tmp_path / "modules"
    package.mkdir()
    (package / "fake_auth.py").write_text(
        "import contextlib\n"
        "CURRENT = []\n"
        "EVENTS = []\n"
        "@contextlib.contextmanager\n"
        "def as_user(identity):\n"
        "    EVENTS.append(('enter', identity))\n"
        "    CURRENT.append(identity)\n"
        "    try:\n"
        "        yield\n"
        "    finally:\n"
        "        CURRENT.pop()\n"
        "        EVENTS.append(('exit', identity))\n"
        "def broken(identity):\n"
        "    raise RuntimeError('secret ' + identity)\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(package))
    return package


def current_user() -> str:
    import fake_auth  # type: ignore[import-not-found]

    return fake_auth.CURRENT[-1] if fake_auth.CURRENT else "nobody"


def test_as_user_context_wraps_real_calls_only(
    identity_module: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, read_log: ReadLog
) -> None:
    import fake_auth  # type: ignore[import-not-found]

    fake_auth.EVENTS.clear()
    config = config_of(
        tools={
            "current_user": {"safe": True, "sensitive": False},
            "delete_record": {"forbidden": True},
        },
        fixtures=FIXTURES,
        target={"as_user": "fake_auth:as_user"},
    )
    session = build_session(config, run_id="r", mode="agent", actor="attacker")
    write = write_session(session, tmp_path)
    monkeypatch.setenv(SESSION_ENV, str(write.path))
    real, dry = gazua.wrap([current_user, delete_record])

    assert real() == "attacker-1"
    assert dry(3) == "ok"

    assert fake_auth.EVENTS == [("enter", "attacker-1"), ("exit", "attacker-1")]
    actors = [record["actor"] for record in read_log(write.call_log)]
    assert actors == [{"id": "attacker-1", "source": "as_user"}] * 2


def test_failing_identity_hook_blocks_the_call(
    identity_module: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, read_log: ReadLog
) -> None:
    config = config_of(
        tools={"read_record": {"safe": True, "sensitive": False}},
        fixtures=FIXTURES,
        target={"as_user": "fake_auth:broken"},
    )
    write = write_session(
        build_session(config, run_id="r", mode="agent", actor="attacker"), tmp_path
    )
    monkeypatch.setenv(SESSION_ENV, str(write.path))
    (proxy,) = gazua.wrap([read_record])

    with pytest.raises(GazuaBlockedError) as blocked:
        proxy(1)

    assert blocked.value.reason == "identity_hook"
    assert calls.seen == []
    assert read_log(write.call_log)[0]["block_reason"] == "identity_hook"
    assert "secret" not in write.call_log.read_text(encoding="utf-8")


def test_invoke_as_refuses_non_safe_tools(tools_mode: Callable[..., Any], tmp_path: Path) -> None:
    config = config_of(
        tools={
            "delete_record": {"safe": False, "forbidden": True},
            "read_record": {"safe": True},
        },
        fixtures={"attacker": {"id": "attacker-1"}},
    )
    invoke = tools_mode(config, delete_record, read_record, no_actor)

    for name in ("delete_record", "read_record", "no_actor"):
        with pytest.raises(NotSafeToCall):
            invoke(name, "attacker", record_id=1)
    with pytest.raises(InvocationRefused) as missing:
        invoke("absent", "attacker")

    assert missing.value.reason == "tool_not_found"
    assert calls.seen == []
    assert not (tmp_path / "calls.jsonl").exists()


def test_invoke_as_needs_the_identity_fixture(tools_mode: Callable[..., Any]) -> None:
    config = config_of(tools={"no_actor": {"safe": True, "sensitive": False}})
    invoke = tools_mode(config, no_actor)

    with pytest.raises(InvocationRefused) as refused:
        invoke("no_actor", "victim", record_id=1)

    assert refused.value.reason == "missing_identity"
