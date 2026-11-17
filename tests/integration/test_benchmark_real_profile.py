import json
import sys
from pathlib import Path

import pytest
from benchmarks.selftest.__main__ import REAL_UNAVAILABLE, main

from conftest import ROOT, build_clean_environment, run_process


def real_config(tmp_path: Path, cost: float | None) -> Path:
    limits = {} if cost is None else {"cost_per_run": cost}
    path = tmp_path / "gazua.yaml"
    path.write_text(
        json.dumps({"schema_version": 1, "entrypoint": "agent:entrypoint", "limits": limits}),
        encoding="utf-8",
    )
    return path


@pytest.fixture(autouse=True)
def outside_ci(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CI", raising=False)


def test_real_profile_requires_explicit_budget(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = real_config(tmp_path, 0.05)

    assert main(["--profile", "real", "--real-config", str(config)]) == 2
    assert "--max-cost is required" in capsys.readouterr().err
    assert main(["--profile", "real", "--max-cost", "5"]) == 2
    assert "--real-config is required" in capsys.readouterr().err
    assert main(["--profile", "real", "--max-cost", "0", "--real-config", str(config)]) == 2
    assert main(["--profile", "real", "--max-cost", "5", "--real-config", str(config)]) == 2
    assert REAL_UNAVAILABLE in capsys.readouterr().err
    # A real budget is never accepted by the simulated profiles.
    assert main(["--max-cost", "5", "--mold", "idor-01"]) == 2


def test_missing_cost_is_not_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    for cost in (None, 0):
        config = real_config(tmp_path, cost)
        assert main(["--profile", "real", "--max-cost", "5", "--real-config", str(config)]) == 2
        assert "positive limits.cost_per_run" in capsys.readouterr().err


def test_ci_never_starts_paid_profile(tmp_path: Path) -> None:
    config = real_config(tmp_path, 0.05)
    environment = {**build_clean_environment(), "CI": "true"}
    command = [
        sys.executable,
        "-m",
        "benchmarks.selftest",
        "--profile",
        "real",
        "--max-cost",
        "5",
        "--real-config",
        str(config),
    ]
    result = run_process(command, cwd=ROOT, env=environment)
    assert result.returncode == 2
    assert "never runs in CI" in result.stderr
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "--profile real" not in workflow
    assert "--profile full" not in workflow
