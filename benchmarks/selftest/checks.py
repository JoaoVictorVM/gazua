"""Auxiliary checks that are not target cells: spy, canary, report HTML, tasks, CLI and tests.

Each check reads real artifacts of this benchmark run or runs a real process. The pytest
checks run a reviewed, explicit file selection, never a command built from catalog ids, and
none of them calls the benchmark back.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Final

from .targets.spy import read_effects

UNSAFE_TOOLS: Final = ("notify_partner",)
PAYLOAD_MARKERS: Final = ("GAZUA-OUTPUT-MARKER", "data-gazua=")
CREDENTIAL_SHAPE: Final = re.compile(
    r"(_API_KEY|_TOKEN|_SECRET|_PASSWORD|^AWS_|^PYPI_)", re.IGNORECASE
)
PROCESS_TIMEOUT: Final = 900.0


@dataclass(frozen=True, slots=True)
class CheckResult:
    outcome: str
    diagnostics: tuple[str, ...] = ()

    @classmethod
    def of(cls, problems: Iterable[str]) -> CheckResult:
        found = tuple(sorted(set(problems)))
        return cls("failed" if found else "passed", found)


def clean_environment() -> dict[str, str]:
    """The environment of child processes: no credential-shaped variable, no checkout path."""
    return {
        name: value
        for name, value in os.environ.items()
        if name not in {"PYTHONPATH", "VIRTUAL_ENV"} and not CREDENTIAL_SHAPE.search(name)
    }


def spy_check(vulnerable: Sequence[Path], others: Sequence[Path]) -> CheckResult:
    """Zero real calls of tools that are not safe, while the paths that reach them ran."""
    problems: list[str] = []
    seen: Counter[str] = Counter()
    for root in [*vulnerable, *others]:
        seen.update(item["kind"] for item in read_effects(root))
    for name in UNSAFE_TOOLS:
        if seen[name]:
            problems.append("unsafe_tool_really_called")
    if seen["entrypoint_called"]:
        problems.append("entrypoint_called_in_tools_mode")
    if seen["credential_read"]:
        problems.append("credential_read")
    if seen["network"]:
        problems.append("external_network_attempt")
    reached: Counter[str] = Counter()
    for root in vulnerable:
        reached.update(item["kind"] for item in read_effects(root))
    # The nested call to the unsafe tool happens inside refund, and get_invoice is async.
    if not reached["refund"]:
        problems.append("nested_unsafe_path_not_exercised")
    if not reached["get_invoice"]:
        problems.append("async_path_not_exercised")
    return CheckResult.of(problems)


def _reports(root: Path) -> list[Path]:
    folder = root / ".gazua"
    return [folder / name for name in ("report.html", "report.md", "run.json")]


def canary_check(vulnerable: Sequence[Path], canary: str, detected: bool) -> CheckResult:
    """The canary is detected by its native signal and reports keep it only as a whole value.

    Declared canaries are synthetic test data that local reports show on purpose; text that
    merely contains one must be masked in full. The aggregated summary is checked separately
    and never carries it.
    """
    problems: list[str] = [] if detected else ["canary_not_detected"]
    embedded = re.compile(rf"[A-Za-z0-9_-]{re.escape(canary)}|{re.escape(canary)}[A-Za-z0-9_-]")
    for root in vulnerable:
        for path in _reports(root):
            if not path.is_file():
                problems.append("report_missing")
            elif embedded.search(path.read_text(encoding="utf-8")):
                problems.append("canary_inside_larger_token")
    return CheckResult.of(problems)


class _Tags(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))


def html_problems(html: str) -> list[str]:
    """Structure a browser would parse; this is not a browser execution test."""
    parser = _Tags()
    parser.feed(html)
    problems: list[str] = []
    names = [tag for tag, _ in parser.tags]
    if names.count("script") != 1:
        problems.append("unexpected_script")
    if {"img", "svg", "iframe", "base", "object", "embed", "b"} & set(names):
        problems.append("payload_tag_rendered")
    for tag, attrs in parser.tags:
        if any(name.lower().startswith("on") for name in attrs):
            problems.append("event_handler_attribute")
        if "data-gazua" in attrs:
            problems.append("payload_attribute_rendered")
        if tag == "meta" and (attrs.get("http-equiv") or "").lower() == "refresh":
            problems.append("meta_refresh")
        for name in ("href", "src", "action"):
            value = attrs.get(name)
            if value is not None and not value.startswith("#"):
                problems.append("external_url")
    policy = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', html)
    if policy is None or "default-src &#39;none&#39;" not in policy.group(1):
        problems.append("csp_missing")
    return problems


def xss_check(vulnerable: Sequence[Path]) -> CheckResult:
    problems: list[str] = []
    for root in vulnerable:
        path = root / ".gazua" / "report.html"
        if not path.is_file():
            problems.append("report_missing")
            continue
        html = path.read_text(encoding="utf-8")
        problems.extend(html_problems(html))
        if "GAZUA-OUTPUT-MARKER" not in html:
            problems.append("payload_not_shown_as_text")
    return CheckResult.of(problems)


_LEGITIMATE = """
import asyncio, json, sys
from selftest_target import python_target as target
results = []
for task in target.DATA.legitimate:
    function = getattr(target, task["tool"])
    value = function(**task["arguments"], actor=task["actor"])
    if asyncio.iscoroutine(value):
        value = asyncio.run(value)
    ok = isinstance(value, dict) and all(value.get(k) == v for k, v in task["expect"].items())
    results.append(ok)
plain = target.sink(target.DATA.plain_output)
print(json.dumps({"tasks": results, "plain_output_shown": plain["effect"]}))
"""


def legitimate_check(hardened: Path) -> CheckResult:
    """The hardened target still serves its own users, in its own process."""
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c", _LEGITIMATE],
        cwd=hardened,
        env=clean_environment(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=PROCESS_TIMEOUT,
        check=False,
    )
    if completed.returncode != 0:
        return CheckResult("failed", ("legitimate_process_failed",))
    try:
        document = json.loads(completed.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return CheckResult("failed", ("legitimate_output_invalid",))
    problems: list[str] = []
    if not document["tasks"] or not all(document["tasks"]):
        problems.append("legitimate_task_refused")
    if document["plain_output_shown"]:
        problems.append("plain_output_flagged")
    return CheckResult.of(problems)


def run_cli(workspace: Path, *arguments: str) -> int:
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "gazua", "run", *arguments],
        cwd=workspace,
        env=clean_environment(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=PROCESS_TIMEOUT,
        check=False,
    )
    return completed.returncode


def cli_parity(
    programmatic: Mapping[str, object], command_line: Mapping[str, object]
) -> CheckResult:
    """The command line and the programmatic run agree on exit code, states and findings."""
    problems = [
        f"{name}_differs"
        for name in sorted(set(programmatic) | set(command_line))
        if programmatic.get(name) != command_line.get(name)
    ]
    return CheckResult.of(problems)


def pytest_check(root: Path, tests: Sequence[str]) -> CheckResult:
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *tests],
        cwd=root,
        env=clean_environment(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=PROCESS_TIMEOUT,
        check=False,
    )
    return (
        CheckResult("passed")
        if completed.returncode == 0
        else CheckResult("failed", ("selected_tests_failed",))
    )


def privacy_problems(
    text: str, canary: str, environment: Mapping[str, str] | None = None
) -> list[str]:
    """What the aggregated artifacts must never carry.

    Only credential-shaped variables are secrets: ordinary values, such as the commit CI
    exposes as an environment variable, may legitimately match the provenance.
    """
    problems: list[str] = []
    if canary in text:
        problems.append("canary_in_summary")
    if any(marker in text for marker in PAYLOAD_MARKERS):
        problems.append("payload_in_summary")
    variables = os.environ if environment is None else environment
    for name, value in variables.items():
        if CREDENTIAL_SHAPE.search(name) and len(value) >= 8 and value in text:
            problems.append("credential_in_summary")
            break
    return problems


__all__ = [
    "CheckResult",
    "canary_check",
    "clean_environment",
    "cli_parity",
    "html_problems",
    "legitimate_check",
    "privacy_problems",
    "pytest_check",
    "run_cli",
    "spy_check",
    "xss_check",
]
