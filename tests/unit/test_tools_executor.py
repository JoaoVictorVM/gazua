import itertools
import json
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from tools_factory import config_document, mold

from gazua.config.models import GazuaConfig
from gazua.integration.session import SESSION_ENV
from gazua.modes.tools_executor import NEUTRAL_RESPONSE, execute
from gazua.modes.tools_models import ToolsInventory
from gazua.modes.tools_plan import plan_tools
from gazua.runtime.session_writer import SessionExecution, build_session, write_session
from gazua.runtime.tools import InvocationRefused, NotSafeToCall
from gazua.runtime.worker import ExecutionContext

TARGET = """
import gazua

CALLS = []


def delete_account(actor=None):
    CALLS.append(("delete_account", actor))
    return "deleted"


def get_order(order_id, region, user_id=None, actor=None):
    CALLS.append(("get_order", actor))
    return None


def send_email(to="x", actor=None):
    CALLS.append(("send_email", actor))
    return "sent"


TOOLS = gazua.wrap(
    {"delete_account": delete_account, "get_order": get_order, "send_email": send_email}
)


def entrypoint(message):
    raise AssertionError("the entrypoint is never called in tools mode")
"""
_numbers = itertools.count()


@pytest.fixture
def target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[str, Path]]:
    name = f"executor_target_{next(_numbers)}"
    package = tmp_path / "modules"
    package.mkdir()
    (package / f"{name}.py").write_text(TARGET, encoding="utf-8")
    monkeypatch.syspath_prepend(str(package))
    monkeypatch.delenv(SESSION_ENV, raising=False)
    yield name, tmp_path
    sys.modules.pop(name, None)


def configuration(module: str, **tools: Any) -> GazuaConfig:
    document = config_document(
        entrypoint=f"{module}:entrypoint",
        tools={
            "delete_account": {"safe": True, "forbidden": True, "actor_arg": "actor"},
            "get_order": {"safe": True, "sensitive": False, "owner_arg": "user_id"},
            "send_email": {"sensitive": True, "actor_arg": "actor"},
            **tools,
        },
    )
    document["fixtures"]["victim"]["records"] = [
        {"tool": "get_order", "id_arg": "order_id", "id": "order-victim-1"}
    ]
    document["target"] = {"as_user": f"{module}:entrypoint"}
    return GazuaConfig.model_validate(document)


def described(config: GazuaConfig) -> ToolsInventory:
    def delete_account(actor: Any = None) -> str:
        return "deleted"

    def get_order(order_id: Any, region: Any, user_id: Any = None, actor: Any = None) -> None:
        return None

    def send_email(to: Any = "x", actor: Any = None) -> str:
        return "sent"

    from tools_factory import inventory

    return inventory(
        config,
        {"delete_account": delete_account, "get_order": get_order, "send_email": send_email},
    )


Run = Callable[..., tuple[Any, list[dict[str, Any]], list[Any]]]


@pytest.fixture
def run(target: tuple[str, Path], monkeypatch: pytest.MonkeyPatch) -> Run:
    module, root = target

    def run_request(
        config: GazuaConfig, request: dict[str, Any]
    ) -> tuple[Any, list[dict[str, Any]], list[Any]]:
        folder = root / f"exec-{next(_numbers)}"
        session = build_session(
            config,
            run_id="GAZUA-run-test",
            mode="tools",
            actor=request.get("actor"),
            execution=SessionExecution(execution_id="GAZUA-exec-0001", max_tool_calls=50),
        )
        written = write_session(session, folder)
        # The worker points the target at its session before importing it, as done here.
        monkeypatch.setenv(SESSION_ENV, str(written.path))
        context = ExecutionContext(
            run_id="GAZUA-run-test",
            execution_id="GAZUA-exec-0001",
            config=config,
            entrypoint=config.entrypoint,
            directory=folder,
            session_path=written.path,
            call_log=written.call_log,
        )
        result = execute(request, context)
        log = written.call_log
        records = (
            [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
            if log.is_file()
            else []
        )
        return result, records, list(sys.modules[module].CALLS)

    return run_request


def request_for(config: GazuaConfig, mold_id: str, tool: str) -> dict[str, Any] | None:
    plan = plan_tools([mold(mold_id)], config, described(config))
    found = [item for item in plan.attacks if item.context.tool_name == tool]
    [attack] = found
    return None if attack.request is None else attack.request.model_dump(mode="json")


def test_missing_required_argument_is_not_tested(run: Run, target: tuple[str, Path]) -> None:
    config = configuration(target[0])
    plan = plan_tools([mold("idor-01")], config, described(config))

    [attack] = plan.attacks
    assert attack.request is None
    assert attack.context.impediment is not None
    assert attack.context.impediment.reason == "missing_tool_arguments"
    [diagnostic] = attack.diagnostics
    assert (diagnostic.code, diagnostic.arguments) == ("missing_tool_arguments", ["region"])

    forged = {
        "key": f"{attack.context.attack_key}:r1",
        "mold_id": "idor-01",
        "repetition": 1,
        "mode": "tools",
        "executor": "gazua.modes.tools_executor:execute",
        "payload": {
            "attack_key": attack.context.attack_key,
            "tool_name": "get_order",
            "record_index": 0,
            "canary_index": None,
            "language": "en",
            "mold": mold("idor-01").model_dump(mode="json", exclude_unset=True),
        },
        "actor": "attacker",
    }
    with pytest.raises(InvocationRefused) as refused:
        run(config, forged)
    assert refused.value.reason == "inventory_changed"


def test_omitted_actor_is_not_reinjected(run: Run, target: tuple[str, Path]) -> None:
    config = configuration(target[0])
    omitted = request_for(config, "permission-02", "delete_account")
    declared = request_for(config, "permission-01", "delete_account")
    assert omitted is not None
    assert declared is not None
    assert omitted["actor"] is None

    result, records, calls = run(config, omitted)
    assert result == {
        "output": {"gazua_observation_version": 1, "response": NEUTRAL_RESPONSE, "observations": []}
    }
    assert calls == [("delete_account", None)]
    assert [record["actor"] for record in records] == [{"id": None, "source": "none"}]
    assert "actor" not in records[0]["arguments"]

    _, records, calls = run(config, declared)
    assert calls[-1] == ("delete_account", "attacker-1")
    assert records[-1]["actor"] == {"id": "attacker-1", "source": "actor_arg"}

    impersonating = {**declared, "actor": "victim"}
    with pytest.raises(InvocationRefused) as refused:
        run(config, impersonating)
    assert refused.value.reason == "request_invalid"


def test_cannot_fall_back_to_original(run: Run, target: tuple[str, Path]) -> None:
    released = configuration(
        target[0], send_email={"safe": True, "sensitive": True, "actor_arg": "actor"}
    )
    request = request_for(released, "permission-03", "send_email")
    assert request is not None
    blocked = configuration(target[0])
    assert request_for(blocked, "permission-03", "send_email") is None

    with pytest.raises((NotSafeToCall, InvocationRefused)):
        run(blocked, request)
    renamed = {**request, "payload": {**request["payload"], "tool_name": "absent"}}
    with pytest.raises(InvocationRefused):
        run(released, renamed)

    assert sys.modules[target[0]].CALLS == []
