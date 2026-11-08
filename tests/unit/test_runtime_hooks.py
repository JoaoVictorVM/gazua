import sys
from pathlib import Path

import pytest

from gazua.runtime import HookError, ResetFailed, call_entrypoint, call_reset

TARGET = """
import asyncio
CALLS = []

def entrypoint(message):
    CALLS.append(message)
    return "echo " + message

async def async_entrypoint(message):
    await asyncio.sleep(0)
    return "async " + message

def number_entrypoint(message):
    return 42

def failing_entrypoint(message):
    raise ValueError("private value " + message)

def exiting_entrypoint(message):
    raise SystemExit(3)

def reset():
    CALLS.append("reset")

def failing_reset():
    raise RuntimeError("private state")
"""


@pytest.fixture
def target_module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    name = f"hook_target_{tmp_path.name.replace('-', '_')}"
    (tmp_path / f"{name}.py").write_text(TARGET, encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    return name


def test_entrypoint_sync_async_and_non_string_response(target_module: str) -> None:
    assert call_entrypoint(f"{target_module}:entrypoint", "hi") == "echo hi"
    assert call_entrypoint(f"{target_module}:async_entrypoint", "hi") == "async hi"

    with pytest.raises(HookError) as raised:
        call_entrypoint(f"{target_module}:number_entrypoint", "hi")

    assert raised.value.reason == "The response is int, expected str."
    assert raised.value.diagnostic.code == "entrypoint_error"


@pytest.mark.parametrize(
    ("attribute", "expected"),
    [
        ("failing_entrypoint", "The call raised ValueError."),
        ("exiting_entrypoint", "The call raised SystemExit."),
    ],
)
def test_hook_errors_expose_class_but_not_values(
    target_module: str, attribute: str, expected: str
) -> None:
    with pytest.raises(HookError) as raised:
        call_entrypoint(f"{target_module}:{attribute}", "secret-message")

    assert raised.value.reason == expected
    assert "secret-message" not in str(raised.value)
    assert "private" not in str(raised.value)


def test_unimportable_entrypoint_is_a_hook_error(tmp_path: Path) -> None:
    with pytest.raises(HookError) as raised:
        call_entrypoint("module_that_does_not_exist_here:entrypoint", "hi")

    assert "missing module module_that_does_not_exist_here" in raised.value.reason


def test_reset_failure_is_reported_not_swallowed(target_module: str) -> None:
    assert call_reset(None) is False
    assert call_reset(f"{target_module}:reset") is True
    assert sys.modules[target_module].CALLS == ["reset"]

    with pytest.raises(ResetFailed) as raised:
        call_reset(f"{target_module}:failing_reset")

    assert raised.value.reason == "The call raised RuntimeError."
    assert raised.value.diagnostic.code == "reset_error"
    assert "private" not in str(raised.value)


def test_hooks_import_target_only_when_called(target_module: str) -> None:
    import gazua.runtime  # noqa: F401

    assert target_module not in sys.modules

    call_entrypoint(f"{target_module}:entrypoint", "first")
    call_entrypoint(f"{target_module}:entrypoint", "second")

    assert sys.modules[target_module].CALLS == ["first", "second"]
