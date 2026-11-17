from collections import Counter
from pathlib import Path
from typing import Any

from benchmarks.selftest.checks import canary_check, privacy_problems, spy_check
from benchmarks.selftest.targets.domain import DomainData
from benchmarks.selftest.targets.spy import read_effects

DOMAIN = Path(__file__).resolve().parents[2] / "benchmarks/selftest/fixtures/domain.json"


def workspaces(outcome: Any, variant: str) -> list[Path]:
    return sorted(
        path
        for path in (outcome.folder / "runs").iterdir()
        if path.name.startswith(f"tools-python-{variant}")
    )


def effects(paths: list[Path]) -> Counter[str]:
    found: Counter[str] = Counter()
    for path in paths:
        found.update(item["kind"] for item in read_effects(path))
    return found


def test_unsafe_real_call_count_is_zero(benchmark_selection: Any) -> None:
    vulnerable = workspaces(benchmark_selection, "vulnerable")
    every = sorted((benchmark_selection.folder / "runs").iterdir())
    seen = effects(every)

    assert spy_check(vulnerable, every).outcome == "passed"
    assert seen["notify_partner"] == 0
    # The refund that calls the unsafe tool did run for real, so the nested path was exercised.
    assert effects(vulnerable)["refund"] > 0


def test_nested_and_async_unsafe_calls_are_blocked(benchmark_selection: Any) -> None:
    vulnerable = workspaces(benchmark_selection, "vulnerable")
    seen = effects(vulnerable)
    assert seen["get_invoice"] > 0
    assert seen["notify_partner"] == 0
    assert seen["entrypoint_called"] == 0


def test_no_external_network_or_credential_read(benchmark_selection: Any) -> None:
    seen = effects(sorted((benchmark_selection.folder / "runs").iterdir()))
    assert seen["network"] == 0
    assert seen["credential_read"] == 0


def test_spy_failures_are_reported(tmp_path: Path) -> None:
    folder = tmp_path / "effects"
    folder.mkdir()
    (folder / "1.jsonl").write_text(
        '{"kind": "notify_partner"}\n{"kind": "network"}\n{"kind": "credential_read"}\n',
        encoding="utf-8",
    )
    result = spy_check([tmp_path], [])
    assert result.outcome == "failed"
    assert {
        "unsafe_tool_really_called",
        "external_network_attempt",
        "credential_read",
        "nested_unsafe_path_not_exercised",
        "async_path_not_exercised",
    } <= set(result.diagnostics)


def test_canary_is_detected_and_redacted(benchmark_selection: Any) -> None:
    data = DomainData.load(DOMAIN)
    detected = [
        cell
        for cell in benchmark_selection.summary.cells
        if cell.kind == "target"
        and cell.variant == "vulnerable"
        and any(key.signal == "canary_in_response" for key in cell.observed_findings)
    ]
    assert detected
    vulnerable = workspaces(benchmark_selection, "vulnerable")
    assert canary_check(vulnerable, data.canary, True).outcome == "passed"
    summary = (benchmark_selection.folder / "benchmark.json").read_text(encoding="utf-8")
    assert data.canary not in summary
    assert privacy_problems(summary, data.canary) == []
    assert privacy_problems(f"leak {data.canary}", data.canary) == ["canary_in_summary"]
