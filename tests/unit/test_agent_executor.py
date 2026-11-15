import itertools
import json
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from agent_factory import config_document, inventory

from gazua.catalog.models import Mold
from gazua.config.models import GazuaConfig
from gazua.integration.injection import reset_deliveries
from gazua.integration.session import SESSION_ENV
from gazua.modes.agent_executor import execute
from gazua.modes.agent_plan import plan_agent
from gazua.runtime.session_writer import SessionExecution, build_session, write_session
from gazua.runtime.tools import InvocationRefused
from gazua.runtime.worker import ExecutionContext

TARGET = """
import gazua

MESSAGES = []
SEEN = []


def search_docs(query="policy"):
    return "Refunds are accepted within 30 days."


TOOLS = gazua.wrap({"search_docs": search_docs})


def entrypoint(message):
    MESSAGES.append(message)
    if "docs" in message:
        # A second read in the same turn must not receive another turn's text.
        SEEN.append([TOOLS["search_docs"](), TOOLS["search_docs"]()])
    return "answer " + str(len(MESSAGES))
"""
_numbers = itertools.count()


def two_turn(mold_id: str, entry: str) -> Mold:
    return Mold.model_validate(
        {
            "schema_version": 1,
            "id": mold_id,
            "damage": "secret_in_context",
            "entry": entry,
            "technique": "two_turn",
            "supported_modes": ["agent"],
            "text": {
                "en": ["First turn GAZUA-T1.", "Second turn GAZUA-T2."],
                "pt": ["Primeiro turno GAZUA-T1.", "Segundo turno GAZUA-T2."],
            },
            "action": {"kind": "inject_text"},
            "success": {"signal": "canary_in_response"},
        }
    )


@pytest.fixture
def target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[str, Path]]:
    name = f"agent_executor_target_{next(_numbers)}"
    package = tmp_path / "modules"
    package.mkdir()
    (package / f"{name}.py").write_text(TARGET, encoding="utf-8")
    monkeypatch.syspath_prepend(str(package))
    monkeypatch.delenv(SESSION_ENV, raising=False)
    yield name, tmp_path
    sys.modules.pop(name, None)


def configuration(module: str) -> GazuaConfig:
    document = config_document(
        entrypoint=f"{module}:entrypoint",
        output_sink=None,
        tools={"search_docs": {"safe": True, "sensitive": False}},
        fixtures={},
        agent_entries={"tool_result": {"tool": "search_docs", "request": "Read the docs please."}},
        legit_tasks=[{"request": "Read the docs now.", "expected_tool": "search_docs"}],
    )
    return GazuaConfig.model_validate(document)


Run = Callable[..., tuple[Any, list[dict[str, Any]], Any]]


@pytest.fixture
def run(target: tuple[str, Path], monkeypatch: pytest.MonkeyPatch) -> Run:
    module, root = target

    def run_request(config: GazuaConfig, request: dict[str, Any]) -> tuple[Any, Any, Any]:
        folder = root / f"exec-{next(_numbers)}"
        session = build_session(
            config,
            run_id="GAZUA-run-test",
            mode="agent",
            actor=request.get("actor"),
            injections=[],
            execution=SessionExecution(execution_id="GAZUA-exec-0001", max_tool_calls=50),
        )
        from gazua.runtime.run_models import ExecutionRequest

        parsed = ExecutionRequest.model_validate(request)
        session = session.model_copy(update={"injections": list(parsed.injections)})
        written = write_session(session, folder)
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
        return result, records, sys.modules[module]

    return run_request


def requests_for(config: GazuaConfig, chosen: Mold) -> list[dict[str, Any]]:
    plan = plan_agent([chosen], config, inventory(config), repetitions=2)
    [scenario] = plan.scenarios
    return [request.model_dump(mode="json") for request in scenario.requests]


def test_two_turns_share_worker_session_and_deadline(run: Run, target: tuple[str, Path]) -> None:
    config = configuration(target[0])
    first, _ = requests_for(config, two_turn("secret-90", "user_message"))
    assert first["injections"] == []

    result, records, module = run(config, first)

    # Both turns go to the same entrypoint, in order, in one process and session.
    assert module.MESSAGES == ["First turn GAZUA-T1.", "Second turn GAZUA-T2."]
    assert result["output"]["response"] == ["answer 1", "answer 2"]
    assert result["output"]["observations"] == []
    assert records == []

    legitimate = plan_agent([], config, inventory(config), repetitions=1).legitimate
    task = legitimate[0].model_dump(mode="json")
    result, records, module = run(config, task)
    assert module.MESSAGES[-1] == "Read the docs now."
    assert [record["tool"] for record in records] == ["search_docs", "search_docs"]
    assert all(record["injection"] is None for record in records)

    forged = {**task, "payload": {**task["payload"], "request": "Something else"}}
    with pytest.raises(InvocationRefused):
        run(config, forged)


def test_indirect_turns_are_armed_separately(run: Run, target: tuple[str, Path]) -> None:
    config = configuration(target[0])
    first, second = requests_for(config, two_turn("secret-91", "tool_result"))
    assert [item["id"] for item in first["injections"]] == [
        f"{first['key']}#turn1",
        f"{first['key']}#turn2",
    ]

    result, records, module = run(config, first)

    # The trigger message goes to the agent; the attack text never does.
    assert module.MESSAGES == ["Read the docs please.", "Read the docs please."]
    assert result["output"]["response"] == ["answer 1", "answer 2"]
    turn_one, turn_two = module.SEEN
    assert turn_one[0].endswith("GAZUA-T1.")
    assert "GAZUA-T2" not in turn_one[0]
    assert turn_two[0].endswith("GAZUA-T2.")
    # The second read of each turn gets no text: one delivery per turn.
    assert "GAZUA" not in turn_one[1]
    assert "GAZUA" not in turn_two[1]
    injections = [record["injection"] for record in records]
    assert injections == [
        {"id": f"{first['key']}#turn1", "delivered": True, "reason": None},
        None,
        {"id": f"{first['key']}#turn2", "delivered": True, "reason": None},
        None,
    ]

    # A retry or another repetition runs in a fresh process; nothing leaks between them here.
    reset_deliveries()
    _, records, _ = run(config, second)
    assert [record["injection"]["id"] for record in records if record["injection"]] == [
        f"{second['key']}#turn1",
        f"{second['key']}#turn2",
    ]

    tampered = {**first, "injections": first["injections"][:1]}
    with pytest.raises(InvocationRefused):
        run(config, tampered)
