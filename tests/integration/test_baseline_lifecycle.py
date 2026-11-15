from typing import Any

from verify_support import accepted, gazua

from gazua.reports.lifecycle import LifecycleLock, apply_retention


def test_lock_serializes_run_verify_baseline_and_clean(tools_project: Any) -> None:
    accepted(tools_project.root, "--tools", "--mold", "idor-01")
    path = tools_project.root / "gazua-baseline.json"
    before = path.read_bytes()
    runs = sorted((tools_project.root / ".gazua" / "runs").iterdir())
    tools_project.harden()
    tools_project.clear_effects()

    with LifecycleLock(tools_project.root):
        results = [
            gazua(tools_project.root, "baseline"),
            gazua(tools_project.root, "verify", "idor-01"),
            gazua(tools_project.root, "run", "--tools", "--mold", "idor-01"),
            gazua(tools_project.root, "clean"),
        ]

    for result in results:
        assert result.returncode == 2
        assert "Another Gazua command" in result.stderr
    assert path.read_bytes() == before
    assert sorted((tools_project.root / ".gazua" / "runs").iterdir()) == runs
    assert not [item for item in tools_project.effects() if item["kind"] == "get_order"]


def test_clean_and_retention_preserve_baseline(tools_project: Any) -> None:
    accepted(tools_project.root, "--tools", "--mold", "idor-01")
    path = tools_project.root / "gazua-baseline.json"
    before = path.read_bytes()

    with LifecycleLock(tools_project.root):
        apply_retention(tools_project.root, keep=0)
    assert path.read_bytes() == before

    cleaned = gazua(tools_project.root, "clean")

    assert cleaned.returncode == 0, cleaned.stderr
    assert not (tools_project.root / ".gazua" / "run.json").exists()
    assert path.read_bytes() == before
    again = tools_project.cli("--tools", "--mold", "idor-01")
    assert again.returncode == 0
    assert "1 known finding, 0 new" in again.stdout
