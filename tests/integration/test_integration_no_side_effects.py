import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

Spy = Callable[..., dict[str, Any]]
Runner = Callable[..., Any]

HEAVY_DEPENDENCIES = ("typer", "pydantic", "yaml", "jinja2")


def opened_inside(report: dict[str, Any], folder: Path) -> set[str]:
    root = str(folder.resolve()).lower()
    return {
        Path(path).name
        for path in report["opened_paths"]
        if str(Path(path).resolve()).lower().startswith(root)
    }


def test_wrapper_does_not_touch_network_credentials_or_unlisted_paths(
    run_spied: Spy, workdir: Path
) -> None:
    session = workdir / "session.json"
    session.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "run_id": "spy",
                "mode": "agent",
                "call_log": "calls.jsonl",
                "actor": None,
                "as_user": None,
                "tools": {
                    "read_note": {
                        "dry_run": False,
                        "actor_arg": None,
                        "has_dry_run_return": False,
                        "dry_run_return": None,
                    },
                    "send_email": {
                        "dry_run": True,
                        "actor_arg": None,
                        "has_dry_run_return": True,
                        "dry_run_return": "queued",
                    },
                },
                "injections": [],
            }
        ),
        encoding="utf-8",
    )

    inside = run_spied("wrap", str(session))
    outside = run_spied("wrap")
    control = run_spied("control")

    assert inside["exit_code"] == 0
    assert inside["results"] == ["note a", "queued"]
    assert outside["results"] == ["note a", "sent to b"]
    for report in (inside, outside):
        assert report["network"] == []
        assert report["credential_reads"] == []
        assert report["environment_listed"] is False
    assert opened_inside(inside, workdir) == {"session.json", "calls.jsonl"}
    assert opened_inside(outside, workdir) == set()
    assert control["network"]
    assert control["credential_reads"]


def test_importing_gazua_loads_only_the_standard_library(
    run_isolated: Runner, tmp_path: Path
) -> None:
    probe = (
        "import sys, gazua\n"
        f"print([name for name in {HEAVY_DEPENDENCIES!r} if name in sys.modules])\n"
        "print(sorted(name for name in sys.modules if name.startswith('gazua')))\n"
    )

    result = run_isolated([sys.executable, "-c", probe], cwd=tmp_path)

    assert result.returncode == 0, result.stderr
    loaded, modules = result.stdout.splitlines()
    assert loaded == "[]"
    assert "gazua.runtime" not in modules
    assert "gazua.config" not in modules
