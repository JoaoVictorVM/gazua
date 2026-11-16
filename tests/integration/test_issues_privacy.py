import json
import sys
from pathlib import Path
from typing import Any

from issue_support import (
    ATTACK_MARK,
    EMAIL,
    OPT_IN,
    PAYLOAD_MARK,
    PRIVATE,
    SECRET,
    planted_data,
)
from report_support import every_file, gazua, local_environment

from conftest import SPY, run_process

IMPORT_TRAP = (
    "import json, os\n"
    "with open(os.path.join(os.path.dirname(__file__), 'imported.json'), 'w') as handle:\n"
    "    json.dump({'module': __name__}, handle)\n"
)
FORBIDDEN_MODULES = (
    "tools_target",
    "agent_target",
    "openai",
    "anthropic",
    "litellm",
    "google.generativeai",
    "httpx",
    "requests",
)


def _planted(root: Path, **changes: Any) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "run.json").write_text(json.dumps(planted_data(**changes)), encoding="utf-8")


def _spied(root: Path, *arguments: str) -> dict[str, Any]:
    report = root.parent / "spy.json"
    completed = run_process(
        [sys.executable, SPY, report, "cli", "issues", *arguments],
        cwd=root,
        env=local_environment(),
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return json.loads(report.read_text(encoding="utf-8"))


def test_export_opens_no_external_connection(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _planted(root)

    observed = _spied(root, "--from", "run.json", "--include-attack")

    assert observed["exit_code"] == 0
    assert observed["network"] == []
    assert observed["processes"] == []
    assert observed["credential_reads"] == []
    assert observed["environment_listed"] is False


def test_export_imports_no_target_or_provider(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _planted(root)
    (root / "tools_target.py").write_text(IMPORT_TRAP, encoding="utf-8")
    (root / "gazua.yaml").write_text("entrypoint: tools_target:entrypoint\n", encoding="utf-8")

    observed = _spied(root, "--from", "run.json")

    assert not (root / "imported.json").exists()
    assert not set(FORBIDDEN_MODULES) & set(observed["modules"])
    assert not any(path.endswith("gazua.yaml") for path in observed["opened_paths"])
    assert not any(path.endswith("tools_target.py") for path in observed["opened_paths"])


def test_secret_and_pii_canaries_do_not_leak(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _planted(root)

    exported = gazua(root, "issues", "--from", "run.json")

    assert exported.returncode == 0, exported.stderr
    written = every_file(root / ".gazua" / "issues")
    for marker in (*PRIVATE, *OPT_IN, SECRET, EMAIL):
        assert marker not in written, marker
        assert marker not in exported.stdout + exported.stderr, marker


def test_unredacted_source_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _planted(root, redaction="none")

    refused = gazua(root, "issues", "--from", "run.json")

    assert refused.returncode == 2
    assert "--no-redact" in refused.stderr
    assert not (root / ".gazua" / "issues").exists()
    for marker in (*PRIVATE, *OPT_IN, SECRET, EMAIL):
        assert marker not in refused.stdout + refused.stderr


def test_include_attack_does_not_disable_masking(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _planted(root)

    exported = gazua(root, "issues", "--from", "run.json", "--include-attack")

    assert exported.returncode == 0, exported.stderr
    assert "include attack text" in exported.stderr
    written = every_file(root / ".gazua" / "issues")
    assert ATTACK_MARK in written
    assert PAYLOAD_MARK in written
    for marker in (*PRIVATE, SECRET, EMAIL):
        assert marker not in written, marker
        assert marker not in exported.stdout + exported.stderr, marker
