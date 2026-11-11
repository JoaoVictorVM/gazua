import json
import os
import shlex
import subprocess
import sys
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from tools_factory import config, inventory, mold

from gazua.modes.tools import ToolsPreview, operational_failures, reproduction_arguments
from gazua.modes.tools_models import DiscoveredTool, ToolsDiagnostic, ToolsResult
from gazua.modes.tools_plan import plan_tools
from gazua.modes.tools_presentation import (
    inventory_lines,
    render_command,
    result_lines,
    skip_text,
)
from gazua.verdicts.engine import VerdictCollector
from gazua.verdicts.presentation import state_text

HOSTILE = "evil\x1b[31m\nname"


def finished(configuration: Any, described: Any, molds: list[Any], **fields: Any) -> ToolsResult:
    from gazua.modes.tools import _empty_summary  # pyright: ignore[reportPrivateUsage]

    plan = plan_tools(molds, configuration, described)
    summary = _empty_summary("GAZUA-run-20260101000000-abc123", configuration, configuration.limits)
    verdicts = VerdictCollector(plan.contexts, configuration).finalize(summary)
    values: dict[str, Any] = {
        "run_id": summary.run_id,
        "inventory": described,
        "contexts": plan.contexts,
        "engine": summary,
        "verdicts": verdicts,
        "executed": False,
        "diagnostics": plan.diagnostics,
        "reproduction": {
            context.attack_key: reproduction_arguments(context.mold.id, "gazua.yaml")
            for context in plan.contexts
        },
        "exit_code": 2 if operational_failures(summary, verdicts, plan.contexts) else 0,
    }
    values.update(fields)
    return ToolsResult(**values)


def test_missing_safe_uses_required_wording() -> None:
    configuration = config()
    described = inventory(configuration)
    result = finished(configuration, described, [mold("permission-04")])

    by_tool = {
        context.tool_name: item
        for context, item in zip(result.contexts, result.verdicts.results, strict=True)
    }
    assert state_text(by_tool["send_email"]) == "not tested, missing safe: true"
    unsafe = described.get("send_email")
    assert unsafe is not None
    assert skip_text(unsafe) == "not tested, missing safe: true"
    preview = ToolsPreview(
        described,
        plan_tools([mold("permission-04")], configuration, described),
        configuration.limits,
        2,
    )
    lines = inventory_lines(preview)
    assert "  send_email: not tested, missing safe: true" in lines
    assert lines[0].startswith("Tools under test: delete_account, get_invoice, get_order, refund")
    assert any("not tested, missing safe: true" in line for line in result_lines(result))


def test_output_escapes_untrusted_labels() -> None:
    tool = DiscoveredTool(
        name=HOSTILE,
        registered=True,
        safe=False,
        classified=True,
        signature_available=True,
        supports_sync=True,
        supports_async=False,
    )
    configuration = config()
    described = inventory(configuration).model_copy(update={"tools": [tool]})
    preview = ToolsPreview(
        described, plan_tools([], configuration, described), configuration.limits, 1
    )
    result = finished(
        configuration,
        described,
        [],
        diagnostics=[
            ToolsDiagnostic(code="missing_tool_arguments", tool_name=HOSTILE, arguments=["a\rb"])
        ],
    )

    printed = "\n".join([*inventory_lines(preview), *result_lines(result)])
    assert "\x1b" not in printed
    assert "\r" not in printed
    assert "evil?[31m?name" in printed
    assert all(line.isprintable() for line in printed.split("\n"))


hard_values = st.text(
    alphabet=st.characters(blacklist_categories=("Cs", "Cc"), blacklist_characters="\x00"),
    min_size=0,
    max_size=24,
).filter(str.isprintable)
DIFFICULT = [
    "gazua.yaml",
    "my configs/gazua.yaml",
    "it's here/gazua.yaml",
    'say "hi"/gazua.yaml',
    "a;b|c&d$(e)`f`/gazua.yaml",
    "C:\\Program Files\\proj\\",
    "50% off/!bang",
    "",
]


@pytest.mark.parametrize("path", DIFFICULT)
def test_reproduction_round_trips_shell_arguments(path: str) -> None:
    arguments = reproduction_arguments("idor-01", path)

    posix = render_command(arguments, "posix")
    assert posix is not None
    assert shlex.split(posix) == arguments
    windows = render_command(arguments, "windows")
    if any(char in path for char in '"%!'):
        assert windows is None
        return
    assert windows is not None
    if os.name == "nt":
        echo = [sys.executable, "-c", "import json, sys; print(json.dumps(sys.argv[1:]))"]
        command = subprocess.list2cmdline(echo) + " " + windows.split(" ", 1)[1]
        shown = subprocess.run(command, capture_output=True, text=True, check=True)
        assert json.loads(shown.stdout) == arguments[1:]


@settings(max_examples=60, deadline=None)
@given(value=hard_values)
def test_posix_reproduction_round_trips_any_printable_text(value: str) -> None:
    arguments = reproduction_arguments("idor-01", value)

    rendered = render_command(arguments, "posix")

    assert rendered is not None
    assert shlex.split(rendered) == arguments


def test_control_characters_get_no_command() -> None:
    arguments = reproduction_arguments("idor-01", "a\nb")

    assert render_command(arguments, "posix") is None
    assert render_command(arguments, "windows") is None
