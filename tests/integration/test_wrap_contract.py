"""The wrapper contract on a sample project, run in a subprocess like a Gazua execution.

The sample keeps its production code free of Gazua. Only the test entrypoint wraps the tools,
and every real execution leaves a line in ``executions.txt`` so a dry-run can be proven.
"""

import ast
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from gazua.config import load_config
from gazua.integration.session import SESSION_ENV
from gazua.runtime import (
    SessionInjection,
    ToolInventory,
    activate,
    build_session,
    call_entrypoint,
    call_reset,
    read_call_log,
    write_session,
)

Runner = Callable[..., Any]
Spy = Callable[..., dict[str, Any]]

PRODUCTION_TOOLS = """
from pathlib import Path

EXECUTIONS = Path(__file__).resolve().parents[1] / "executions.txt"
CURRENT_USER = []


def _executed(name: str) -> None:
    with EXECUTIONS.open("a", encoding="utf-8") as handle:
        handle.write(name + "\\n")


def lookup_order(order_id: int, user_id: str = "anonymous") -> str:
    _executed("lookup_order")
    return f"order {order_id} for {user_id}"


def refund_order(order_id: int) -> dict:
    _executed("refund_order")
    return {"refunded": order_id}


def search_docs(query: str) -> str:
    _executed("search_docs")
    return f"docs about {query}"


def order_stats(order_id: int) -> dict:
    _executed("order_stats")
    return {"order": order_id}


def whoami() -> str:
    _executed("whoami")
    return CURRENT_USER[-1] if CURRENT_USER else "nobody"


TOOLS = [lookup_order, refund_order, search_docs, order_stats, whoami]
"""

PRODUCTION_AGENT = '''
class Agent:
    """A deterministic stand-in for a model: the first word picks the tool."""

    def __init__(self, tools):
        self.tools = {tool.__name__: tool for tool in tools}

    def reply(self, message: str) -> str:
        action, _, argument = message.partition(" ")
        tool = self.tools[action]
        if not argument:
            return f"{action}: {tool()}"
        result = tool(int(argument)) if argument.isdigit() else tool(argument)
        return f"{action}: {result}"
'''

PRODUCTION_AUTH = """
import contextlib

from app.tools import CURRENT_USER

RESETS = []


@contextlib.contextmanager
def as_user(identity):
    CURRENT_USER.append(identity)
    try:
        yield
    finally:
        CURRENT_USER.pop()


def reset():
    RESETS.append("reset")
"""

TEST_ENTRYPOINT = """
import gazua

from app.agent import Agent
from app.tools import TOOLS


def entrypoint(message: str) -> str:
    return Agent(gazua.wrap(TOOLS)).reply(message)
"""

CONFIGURATION = """
schema_version: 1
entrypoint: gazua_entry:entrypoint
target:
  as_user: app.auth:as_user
  reset: app.auth:reset
tools:
  lookup_order:
    safe: true
    sensitive: false
    actor_arg: user_id
  refund_order:
    sensitive: true
    dry_run_return: {"refunded": "dry-run"}
  search_docs:
    safe: true
    sensitive: false
  order_stats:
    safe: true
    sensitive: false
  whoami:
    safe: true
    sensitive: false
fixtures:
  attacker:
    id: attacker-1
  victim:
    id: victim-1
"""


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / "app").mkdir(parents=True)
    (root / "app" / "__init__.py").write_text("", encoding="utf-8")
    (root / "app" / "tools.py").write_text(PRODUCTION_TOOLS, encoding="utf-8")
    (root / "app" / "agent.py").write_text(PRODUCTION_AGENT, encoding="utf-8")
    (root / "app" / "auth.py").write_text(PRODUCTION_AUTH, encoding="utf-8")
    (root / "gazua_entry.py").write_text(TEST_ENTRYPOINT, encoding="utf-8")
    (root / "gazua.yaml").write_text(CONFIGURATION, encoding="utf-8")
    return root


def executions(project: Path) -> list[str]:
    path = project / "executions.txt"
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


def run_attack(
    run_isolated: Runner,
    clean_environment: Callable[[], dict[str, str]],
    project: Path,
    message: str,
    **session_options: Any,
) -> tuple[str, list[dict[str, Any]]]:
    """Runs one message the way the run engine will: a subprocess with a session file."""
    config = load_config(project / "gazua.yaml").config
    options = {"run_id": "attack-1", "mode": "agent", **session_options}
    written = write_session(build_session(config, **options), project / ".gazua" / "run")
    probe = (
        "import sys\n"
        "from gazua.runtime import call_entrypoint\n"
        "sys.stdout.write(call_entrypoint('gazua_entry:entrypoint', sys.argv[1]))\n"
    )
    result = run_isolated(
        [sys.executable, "-c", probe, message],
        cwd=project,
        env={**clean_environment(), **written.environment},
    )
    assert result.returncode == 0, result.stderr
    records = [record.model_dump(mode="json") for record in read_call_log(written.call_log).records]
    return result.stdout, records


def test_production_code_imports_nothing_from_gazua(
    project: Path, run_isolated: Runner, clean_environment: Callable[[], dict[str, str]]
) -> None:
    for module in (project / "app").glob("*.py"):
        tree = ast.parse(module.read_text(encoding="utf-8"))
        imported = [
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        ] + [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        assert not any(name.split(".")[0] == "gazua" for name in imported), module.name

    response, records = run_attack(
        run_isolated, clean_environment, project, "lookup_order 7", actor="attacker"
    )

    assert response == "lookup_order: order 7 for attacker-1"
    assert executions(project) == ["lookup_order"]
    assert records[0]["actor"] == {"id": "attacker-1", "source": "actor_arg"}


def test_decorated_function_matches_original_outside_a_run(run_spied: Spy) -> None:
    outside = run_spied("wrap")
    control = run_spied("control")

    assert outside["exit_code"] == 0
    assert outside["results"] == ["note a", "sent to b"]
    assert outside["network"] == []
    assert "socket.connect" in control["network"]


def test_non_safe_tool_never_executes_in_agent_session(
    project: Path, run_isolated: Runner, clean_environment: Callable[[], dict[str, str]]
) -> None:
    response, records = run_attack(
        run_isolated, clean_environment, project, "refund_order 9", actor="attacker"
    )

    assert executions(project) == []
    assert response == "refund_order: {'refunded': 'dry-run'}"
    assert (records[0]["tool"], records[0]["dry_run"], records[0]["low_fidelity"]) == (
        "refund_order",
        True,
        False,
    )


def test_missing_dry_run_return_gives_ok_and_low_fidelity(
    project: Path, run_isolated: Runner, clean_environment: Callable[[], dict[str, str]]
) -> None:
    configuration = project / "gazua.yaml"
    configuration.write_text(
        configuration.read_text(encoding="utf-8").replace(
            "  order_stats:\n    safe: true\n", "  order_stats:\n    safe: false\n"
        ),
        encoding="utf-8",
    )

    response, records = run_attack(run_isolated, clean_environment, project, "order_stats 4")

    assert response == "order_stats: ok"
    assert executions(project) == []
    assert records[0]["low_fidelity"] is True

    config = load_config(configuration).config
    session = build_session(config, run_id="inventory", mode="agent")
    run_folder = project / ".gazua" / "inventory"
    run_folder.mkdir(parents=True)
    sys.path.insert(0, str(project))
    try:
        with activate(session, run_folder):
            call_entrypoint("gazua_entry:entrypoint", "order_stats 5")
        inventory = ToolInventory.collect(config)
    finally:
        sys.path.remove(str(project))
        for name in [name for name in sys.modules if name.startswith(("app", "gazua_entry"))]:
            del sys.modules[name]

    assert "order_stats" in inventory.low_fidelity
    assert "order_stats" in inventory.summary().low_fidelity


def test_injection_through_tool_result_including_rag_tool(
    project: Path, run_isolated: Runner, clean_environment: Callable[[], dict[str, str]]
) -> None:
    injections = [
        SessionInjection(id="rag", tool="search_docs", text="IGNORE PREVIOUS", max_deliveries=1),
        SessionInjection(id="stats", tool="order_stats", text="IGNORE", max_deliveries=1),
    ]

    rag_response, rag_records = run_attack(
        run_isolated, clean_environment, project, "search_docs refunds", injections=injections
    )
    stats_response, stats_records = run_attack(
        run_isolated, clean_environment, project, "order_stats 3", injections=injections
    )

    assert rag_response == "search_docs: docs about refunds\nIGNORE PREVIOUS"
    assert rag_records[0]["injection"] == {"id": "rag", "delivered": True, "reason": None}
    assert "IGNORE" not in stats_response
    assert stats_records[-1]["injection"] == {
        "id": "stats",
        "delivered": False,
        "reason": "unsupported_result_type",
    }


def test_config_declarations_drive_wrapper_identity_and_hooks(
    project: Path, run_isolated: Runner, clean_environment: Callable[[], dict[str, str]]
) -> None:
    as_attacker, attacker_records = run_attack(
        run_isolated, clean_environment, project, "whoami", actor="attacker"
    )
    as_victim, _ = run_attack(run_isolated, clean_environment, project, "whoami", actor="victim")
    refund, _ = run_attack(run_isolated, clean_environment, project, "refund_order 1")

    assert as_attacker == "whoami: attacker-1"
    assert as_victim == "whoami: victim-1"
    assert attacker_records[0]["actor"] == {"id": "attacker-1", "source": "as_user"}
    assert refund == "refund_order: {'refunded': 'dry-run'}"
    assert executions(project) == ["whoami", "whoami"]

    config = load_config(project / "gazua.yaml").config
    sys.path.insert(0, str(project))
    try:
        assert call_reset(config.target.reset) is True
        assert sys.modules["app.auth"].RESETS == ["reset"]
    finally:
        sys.path.remove(str(project))
        for name in [name for name in sys.modules if name.startswith(("app", "gazua_entry"))]:
            del sys.modules[name]


def test_session_environment_is_the_only_switch(
    project: Path, run_isolated: Runner, clean_environment: Callable[[], dict[str, str]]
) -> None:
    probe = (
        "import sys\n"
        "from gazua_entry import entrypoint\n"
        "sys.stdout.write(entrypoint('refund_order 2'))\n"
    )
    environment = clean_environment()
    environment.pop(SESSION_ENV, None)

    result = run_isolated([sys.executable, "-c", probe], cwd=project, env=environment)

    assert result.returncode == 0, result.stderr
    assert result.stdout == "refund_order: {'refunded': 2}"
    assert executions(project) == ["refund_order"]
