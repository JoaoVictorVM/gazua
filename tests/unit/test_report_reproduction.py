import shlex

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gazua.modes.tools import reproduction_arguments
from gazua.modes.tools_presentation import render_command
from gazua.reports.builder import PlainTreatment, reproduction_for
from gazua.runtime.run_models import LimitOverrides

HOSTILE = [
    "a b",
    "it's",
    "$HOME",
    "a;b",
    "100%",
    "x&y",
    "tab\there",
    chr(0x2018) + "curly" + chr(0x2019),
    "@splat",
]


def powershell_split(line: str) -> list[str]:
    """How PowerShell reads bare words and single-quoted strings, the only forms rendered."""
    quotes = "'" + "".join(map(chr, (0x2018, 0x2019, 0x201A, 0x201B)))
    found: list[str] = []
    index = 0
    while index < len(line):
        if line[index] == " ":
            index += 1
            continue
        if line[index] in quotes:
            index += 1
            value = ""
            while True:
                char = line[index]
                if char in quotes:
                    if index + 1 < len(line) and line[index + 1] in quotes:
                        value += char
                        index += 2
                        continue
                    index += 1
                    break
                value += char
                index += 1
            found.append(value)
        else:
            end = line.find(" ", index)
            end = len(line) if end == -1 else end
            found.append(line[index:end])
            index = end
    return found


@pytest.mark.parametrize("value", [item for item in HOSTILE if "\t" not in item])
def test_posix_and_powershell_commands_round_trip(value: str) -> None:
    arguments = reproduction_arguments("idor-01", value)

    posix = render_command(arguments, "posix")
    powershell = render_command(arguments, "powershell")

    assert posix is not None
    assert shlex.split(posix) == arguments
    assert powershell is not None
    assert powershell_split(powershell) == arguments


@given(st.text(alphabet=st.characters(blacklist_categories=("Cc", "Cs", "Zl", "Zp")), min_size=1))
def test_powershell_round_trips_printable_text(value: str) -> None:
    arguments = ["gazua", "run", "--config", value]
    rendered = render_command(arguments, "powershell")
    if rendered is None:
        assert (
            any(char in value for char in '"' + chr(0x201C) + chr(0x201D) + chr(0x201E))
            or not value.isprintable()
        )
        return
    assert powershell_split(rendered) == arguments


def test_cmd_contract_remains_compatible() -> None:
    arguments = reproduction_arguments("idor-01", "my project/gazua.yaml")

    assert render_command(arguments, "windows") == (
        'gazua run --tools --config "my project/gazua.yaml" --mold idor-01'
    )
    assert render_command(reproduction_arguments("idor-01", "100%"), "windows") is None
    assert render_command(reproduction_arguments("idor-01", "a\nb"), "powershell") is None


def test_effective_limit_overrides_are_kept_without_concurrency() -> None:
    overrides = LimitOverrides(max_runs=3, timeout=2.5, max_tool_calls=4, concurrency=8)

    arguments = reproduction_arguments("idor-01", "gazua.yaml", overrides)

    assert arguments[-6:] == ["--max-runs", "3", "--timeout", "2.5", "--max-tool-calls", "4"]
    assert "--concurrency" not in arguments
    assert "--no-redact" not in arguments


class Masking(PlainTreatment):
    def text(self, value: str, field: str) -> str:
        return value.replace("secret", "[redacted-secret]")


def test_redacted_arguments_disable_command() -> None:
    changed = reproduction_for(["gazua", "--config", "secret.yaml"], Masking())
    controlled = reproduction_for(["gazua", "--config", "a\x1b[2Jb"], PlainTreatment())
    kept = reproduction_for(["gazua", "--config", "gazua.yaml"], Masking())

    assert changed.available is False
    assert changed.reason == "argument_redacted"
    assert "secret.yaml" not in changed.argv
    assert controlled.available is False
    assert controlled.reason == "argument_control_characters"
    assert all(item.isprintable() for item in controlled.argv)
    assert kept.available is True
    assert kept.reason is None
