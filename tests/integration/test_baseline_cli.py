import json
from typing import Any

from conftest import run_process


def gazua(project: Any, *arguments: str) -> Any:
    import sys

    return run_process([sys.executable, "-m", "gazua", *arguments], cwd=project.root)


def test_create_reads_run_without_import_or_model_call(tools_project: Any) -> None:
    first = tools_project.cli("--tools", "--mold", "idor-01")
    assert first.returncode == 1, first.stderr
    (tools_project.root / "tools_target.py").unlink()
    tools_project.clear_effects()

    created = gazua(tools_project, "baseline")

    assert created.returncode == 0, created.stderr
    assert "Created baseline gazua-baseline.json: 1 accepted, 0 preserved, 0 reopened" in (
        created.stdout
    )
    assert tools_project.effects() == []
    path = tools_project.root / "gazua-baseline.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    [entry] = document["entries"]
    run = json.loads((tools_project.root / ".gazua" / "run.json").read_text(encoding="utf-8"))
    assert entry["id"] == run["findings"][0]["id"]
    assert entry["status"] == "open"
    assert entry["verification"] is None
    content = path.read_bytes()

    again = gazua(tools_project, "baseline")

    assert again.returncode == 0, again.stderr
    assert "unchanged" in again.stdout
    assert path.read_bytes() == content


def test_create_refuses_reserved_output_and_missing_run(tools_project: Any) -> None:
    missing = gazua(tools_project, "baseline")
    assert missing.returncode == 2
    assert "No run.json at this path." in missing.stderr

    tools_project.cli("--tools", "--mold", "idor-01")
    reserved = gazua(tools_project, "baseline", "--output", ".gazua/baseline.json")
    assert reserved.returncode == 2
    assert "baseline_path_invalid" in reserved.stderr
    assert not (tools_project.root / "gazua-baseline.json").exists()


def test_create_refuses_corrupt_existing_baseline(tools_project: Any) -> None:
    tools_project.cli("--tools", "--mold", "idor-01")
    path = tools_project.root / "gazua-baseline.json"
    path.write_text('{"schema_version": 1, "entries": [', encoding="utf-8")

    result = gazua(tools_project, "baseline")

    assert result.returncode == 2
    assert "baseline_invalid" in result.stderr
    assert path.read_text(encoding="utf-8") == '{"schema_version": 1, "entries": ['


def test_corrupt_baseline_fails_before_target_import(tools_project: Any) -> None:
    module = tools_project.root / "tools_target.py"
    spy = "import pathlib\npathlib.Path('imported').write_text('x')\n"
    module.write_text(spy + module.read_text(encoding="utf-8"), encoding="utf-8")
    path = tools_project.root / "gazua-baseline.json"
    path.write_text('{"schema_version": 1, "revision": NaN}', encoding="utf-8")
    content = path.read_bytes()

    result = tools_project.cli("--tools", "--mold", "idor-01")

    assert result.returncode == 2
    assert "baseline_invalid" in result.stderr
    assert not (tools_project.root / "imported").exists()
    assert tools_project.effects() == []
    assert not (tools_project.root / ".gazua" / "run.json").exists()
    assert path.read_bytes() == content

    newer = tools_project.root / "newer.json"
    newer.write_text('{"schema_version": 7, "entries": []}', encoding="utf-8")
    unsupported = tools_project.cli("--tools", "--baseline", "newer.json")
    assert unsupported.returncode == 2
    assert "baseline_version_unsupported" in unsupported.stderr
    assert tools_project.effects() == []
    assert not (tools_project.root / "imported").exists()

    path.unlink()
    imported = tools_project.cli("--tools", "--mold", "idor-01")
    assert imported.returncode == 1
    assert (tools_project.root / "imported").exists()


def test_explicit_missing_differs_from_absent_default(tools_project: Any) -> None:
    explicit = tools_project.cli("--tools", "--mold", "idor-01", "--baseline", "missing.json")

    assert explicit.returncode == 2
    assert "baseline_missing" in explicit.stderr
    assert tools_project.effects() == []

    absent = tools_project.cli("--tools", "--mold", "idor-01")

    assert absent.returncode == 1
    run = json.loads((tools_project.root / ".gazua" / "run.json").read_text(encoding="utf-8"))
    assert run["baseline"] is None
    assert "known finding" not in absent.stdout


def test_list_rejects_baseline_flags(tools_project: Any) -> None:
    listed = tools_project.cli("--list", "--baseline", "gazua-baseline.json")
    assert listed.returncode == 2
    assert "baseline options apply to --tools and --agent" in listed.stderr

    no_baseline = tools_project.cli("--list", "--no-baseline")
    assert no_baseline.returncode == 2

    both = tools_project.cli("--tools", "--baseline", "x.json", "--no-baseline")
    assert both.returncode == 2
    assert "contradict" in both.stderr
    assert tools_project.effects() == []
