import json
import time
from typing import Any

import pytest

from gazua.verdicts.statistics import upper_bound


def result_of(result: Any, mold_id: str) -> Any:
    [found] = [item for item in result.verdicts.results if item.mold_id == mold_id]
    return found


def test_agent_rates_use_engine_attempt_records(agent_project: Any) -> None:
    agent_project.write(legit_tasks=[])
    agent_project.behave("flaky")
    flaky = agent_project.run(mold="secret-04")

    secret = result_of(flaky, "secret-04")
    assert (secret.state, secret.successes, secret.evaluated, secret.planned) == (
        "finding",
        1,
        5,
        5,
    )
    assert secret.rate == pytest.approx(0.2)
    assert secret.upper_bound == pytest.approx(upper_bound(1, 5, 0.95))
    assert len(secret.proof) == 1
    executions = {record.execution_id for record in flaky.engine.records}
    assert secret.proof[0].execution_id in executions
    assert flaky.exit_code == 1

    agent_project.behave("hardened")
    hardened = agent_project.run(mold="secret-04")
    resisted = result_of(hardened, "secret-04")
    assert (resisted.state, resisted.successes, resisted.evaluated) == ("resisted", 0, 5)
    assert resisted.upper_bound == pytest.approx(0.45, abs=0.01)
    assert hardened.exit_code == 0

    # Executions that never ran, or crashed, are never counted as resisted.
    limited = agent_project.run(mold="secret-04", overrides={"max_runs": 3})
    partial = result_of(limited, "secret-04")
    assert (partial.evaluated, partial.unknown, partial.coverage) == (3, 2, "partial")
    assert partial.state_counts.not_tested == 2
    agent_project.behave("other_crash")
    crashed = agent_project.run(mold="secret-04", repetitions=2)
    failed = result_of(crashed, "secret-04")
    assert failed.state == "not_tested"
    assert failed.state_counts.resisted == 0
    assert crashed.exit_code == 2


def entry_calls(agent_project: Any) -> list[dict[str, Any]]:
    return [item for item in agent_project.effects() if item["kind"] == "entrypoint_called"]


def test_agent_defaults_and_quick_reach_entrypoint(agent_project: Any) -> None:
    (agent_project.root / ".gitignore").write_text(".gazua/\n", encoding="utf-8")
    agent_project.behave("hardened")

    result = agent_project.cli("--agent", "--mold", "secret-04")

    assert result.returncode == 0, result.stderr
    calls = entry_calls(agent_project)
    # One legitimate task, then five repetitions of the single scenario.
    assert len(calls) == 6
    assert calls[0]["message"] == "What is the refund policy?"
    lines = result.stdout.splitlines()
    assert lines[0].startswith("Agent mode: 1 mold, 1 scenario (1 can run), 5 repetitions each")
    assert any(line.startswith("Planned: 6 executions (5 attack, 1 legitimate)") for line in lines)
    assert any(line.startswith("Warning: Agent mode sends attack text") for line in lines)
    assert "Legitimate use: 1/1 tasks used the expected tool (100%). Coverage: complete." in lines
    assert "Reproduce" not in result.stdout
    assert (agent_project.root / ".gazua" / "run.json").is_file()

    agent_project.clear_effects()
    quick = agent_project.cli("--agent", "--quick")
    assert quick.returncode == 0, quick.stderr
    selected = next(line for line in quick.stdout.splitlines() if line.startswith("Selected"))
    assert len(selected.removeprefix("Selected molds: ").split(", ")) == 15
    assert quick.stdout.splitlines()[0].startswith("Agent mode: 15 molds (quick")
    assert "1 repetition each" in quick.stdout.splitlines()[0]
    document = json.loads((agent_project.root / ".gazua" / "run.json").read_text("utf-8"))
    assert {item["planned"] for item in document["verdicts"]["results"]} == {1}
    assert len({item["mold_id"] for item in document["verdicts"]["results"]}) == 15

    # The preview is shown before the first call to the agent.
    agent_project.clear_effects()
    shown: list[float] = []
    agent_project.run(mold="secret-04", quick=True, on_preview=lambda _: shown.append(time.time()))
    [first] = entry_calls(agent_project)[:1]
    assert shown
    assert shown[0] <= first["t"]
