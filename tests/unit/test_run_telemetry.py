import json
import math
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import gazua
from gazua.integration.session import SESSION_ENV
from gazua.integration.telemetry import GazuaRateLimited, report_usage
from gazua.runtime import HookError, RateLimited, call_entrypoint

Runner = Callable[..., Any]

PROBE = """
import json, sys
opened = []
sys.addaudithook(lambda event, args: opened.append(args[0]) if event == "open" else None)
import gazua
before = list(opened)
results = [gazua.report_usage(cost_usd=0.25), gazua.report_usage(cost_usd=0)]
print(json.dumps({
    "results": results,
    "heavy": [name for name in ("pydantic", "typer", "yaml", "jinja2") if name in sys.modules],
    "opened_after_import": [path for path in opened[len(before):] if isinstance(path, str)],
}))
"""

TARGET = """
import gazua

def limited(message):
    raise gazua.GazuaRateLimited(retry_after=3)

def limited_without_wait(message):
    raise gazua.GazuaRateLimited()

def failing(message):
    raise RuntimeError("429 Too Many Requests: private-value-" + message)
"""


def test_usage_api_is_stdlib_only_and_passthrough_without_session(
    run_isolated: Runner, tmp_path: Path
) -> None:
    result = run_isolated([sys.executable, "-c", PROBE], cwd=tmp_path)

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["results"] == [False, False]
    assert report["heavy"] == []
    assert report["opened_after_import"] == []
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("value", [-0.01, math.inf, math.nan, True, "0.1", None])
def test_usage_rejects_values_that_are_not_finite_non_negative_numbers(value: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        report_usage(cost_usd=value)  # type: ignore[arg-type]


def test_usage_inside_an_execution_session_reaches_the_channel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = {
        "schema_version": 2,
        "run_id": "GAZUA-run-1",
        "mode": "agent",
        "call_log": "calls.jsonl",
        "actor": None,
        "as_user": None,
        "tools": {},
        "injections": [],
        "execution_id": "GAZUA-exec-0001",
        "max_tool_calls": 5,
        "events_path": "events.jsonl",
        "receiver": None,
        "usage_reporting": True,
    }
    path = tmp_path / "session.json"
    path.write_text(json.dumps(session), encoding="utf-8")
    monkeypatch.setenv(SESSION_ENV, str(path))

    assert gazua.report_usage(cost_usd=0.1) is True
    assert gazua.report_usage(cost_usd=2) is True

    events = [
        json.loads(line)
        for line in (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert [event["kind"] for event in events] == ["usage", "usage"]
    assert [event["payload"]["cost_usd"] for event in events] == ["0.1", "2"]
    assert [event["seq"] for event in events] == [1, 2]
    assert len({event["payload"]["usage_id"] for event in events}) == 2
    assert all(event["execution_id"] == "GAZUA-exec-0001" for event in events)


def test_typed_rate_limit_survives_entrypoint_error_translation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    name = f"rate_target_{tmp_path.name.replace('-', '_')}"
    (tmp_path / f"{name}.py").write_text(TARGET, encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))

    with pytest.raises(RateLimited) as limited:
        call_entrypoint(f"{name}:limited", "GAZUA-secret")
    assert limited.value.retry_after == 3.0
    assert limited.value.diagnostic.code == "rate_limited"

    with pytest.raises(RateLimited) as without_wait:
        call_entrypoint(f"{name}:limited_without_wait", "x")
    assert without_wait.value.retry_after is None

    # A 429 described only in a message is an ordinary error, never recognized by its text.
    with pytest.raises(HookError) as generic:
        call_entrypoint(f"{name}:failing", "GAZUA-secret")
    assert not isinstance(generic.value, RateLimited)
    assert "private-value" not in str(generic.value)
    assert "429" not in str(generic.value)

    with pytest.raises(ValueError, match="retry_after"):
        GazuaRateLimited(retry_after=-1)


AUTH_PROBE = """
import json, os, sys
reads = []
class Watched(type(os.environ)):
    def __getitem__(self, key):
        reads.append(key)
        return super().__getitem__(key)
os.environ.__class__ = Watched
opened = []
sys.addaudithook(lambda event, args: opened.append(event) if event.startswith("socket.") else None)
from gazua import GazuaAuthenticationError
from gazua.integration import GazuaAuthenticationError as again
error = GazuaAuthenticationError()
print(json.dumps({
    "same": error.__class__ is again,
    "args": list(error.args),
    "providers": [name for name in sys.modules if name in ("openai", "anthropic", "pydantic")],
    "reads": reads,
    "network": opened,
}))
"""

AUTH_TARGET = """
import gazua

def refused(message):
    raise gazua.GazuaAuthenticationError()

def leaked(message):
    raise PermissionError("401 invalid key sk-private-" + message)
"""


def test_authentication_signal_is_stdlib_only_and_keyless(
    run_isolated: Runner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = run_isolated([sys.executable, "-c", AUTH_PROBE], cwd=tmp_path)

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["same"] is True
    assert report["providers"] == []
    assert report["reads"] == []
    assert report["network"] == []
    assert "key" not in " ".join(report["args"]).lower()
    with pytest.raises(TypeError):
        gazua.GazuaAuthenticationError("sk-private")  # type: ignore[call-arg]

    from gazua.runtime.hooks import AuthenticationFailed

    name = f"auth_target_{tmp_path.name.replace('-', '_')}"
    (tmp_path / f"{name}.py").write_text(AUTH_TARGET, encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    with pytest.raises(AuthenticationFailed) as refused:
        call_entrypoint(f"{name}:refused", "GAZUA-secret")
    assert refused.value.code == "agent_authentication_failed"
    assert "GAZUA-secret" not in str(refused.value)

    # A provider error the target did not translate stays a generic failure, named by class.
    with pytest.raises(HookError) as leaked:
        call_entrypoint(f"{name}:leaked", "x")
    assert not isinstance(leaked.value, AuthenticationFailed)
    assert leaked.value.error_type == "PermissionError"
    assert "sk-private" not in str(leaked.value)
