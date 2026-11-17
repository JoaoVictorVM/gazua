import importlib.util
import json
import shutil
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml
from benchmarks.selftest import __main__ as command
from benchmarks.selftest import runner

from conftest import ROOT


def load_gate() -> ModuleType:
    path = ROOT / ".github" / "scripts" / "run_selftest.py"
    spec = importlib.util.spec_from_file_location("run_selftest", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Calls:
    def __init__(self, codes: list[int] | None = None) -> None:
        self.calls: list[list[str]] = []
        self.codes = list(codes or [])

    def __call__(self, arguments: Any) -> int:
        self.calls.append(list(arguments))
        return self.codes.pop(0) if self.codes else 0


def test_changed_mold_cannot_bypass_pair_checks(tmp_path: Path) -> None:
    gate = load_gate()
    head = gate._git("rev-parse", "HEAD").stdout.strip()

    pending = Calls()
    code = gate.gate(
        head,
        run=pending,
        changed=lambda _base: ["memory-01"],
        readme=lambda _p: 0,
        workdir=tmp_path,
    )
    assert code == 1
    assert len(pending.calls) == 1

    future = Calls([0, 2])
    code = gate.gate(
        head,
        run=future,
        changed=lambda _base: ["idor-09"],
        readme=lambda _p: 0,
        workdir=tmp_path,
    )
    assert code == 2
    assert future.calls[1][:2] == ["--profile", "full"]
    assert future.calls[1][-2:] == ["--mold", "idor-09"]

    failing = Calls([1])
    assert (
        gate.gate(head, run=failing, changed=lambda _b: [], readme=lambda _p: 0, workdir=tmp_path)
        == 1
    )
    assert (
        gate.gate(head, run=Calls(), changed=lambda _b: [], readme=lambda _p: 1, workdir=tmp_path)
        == 1
    )


def test_unknown_base_requires_release_gate(tmp_path: Path) -> None:
    gate = load_gate()
    for base in (None, "", "0" * 40, "not-a-sha", "f" * 40):
        calls = Calls()
        assert gate.gate(base, run=calls, readme=lambda _p: 0, workdir=tmp_path) == 0
        assert calls.calls == [["--profile", "release", "--output", str(tmp_path / "release")]]


def test_changed_molds_come_from_catalog_files_only() -> None:
    gate = load_gate()
    assert gate.MOLD_FILE.match("src/gazua/catalog/builtin/idor-01.yaml").group(1) == "idor-01"
    assert gate.MOLD_FILE.match("src/gazua/catalog/builtin/../x.yaml") is None
    assert gate.MOLD_FILE.match("src/gazua/catalog/builtin/a b.yaml") is None
    head = gate._git("rev-parse", "HEAD").stdout.strip()
    assert gate.changed_molds(head) == []


def test_no_secrets_or_pull_request_target() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    job = workflow["jobs"]["benchmark"]
    text = json.dumps(job)
    assert "secrets." not in text
    assert "pull_request_target" not in json.dumps(workflow.get(True, workflow.get("on")))
    assert workflow["permissions"] == {"contents": "read"}
    assert "permissions" not in job
    checkout = job["steps"][0]
    assert checkout["with"]["persist-credentials"] is False
    for step in job["steps"]:
        if "uses" in step:
            assert len(step["uses"].split("@")[1].split()[0]) == 40
    run = next(step for step in job["steps"] if "run_selftest.py" in step.get("run", ""))
    assert "--profile" not in run["run"]
    assert "API_KEY" not in text


def test_future_dependency_blocks_release_promotion(tmp_path: Path) -> None:
    matrix = json.loads((ROOT / "benchmarks/selftest/matrix.json").read_text(encoding="utf-8"))
    for case in matrix["cases"]:
        if case["mold_id"] == "secret-02":
            case.pop("expected_states")
            case["availability"] = "pending_dependency"
            case["dependency"] = "An adapter that does not exist yet."
    broken = tmp_path / "matrix.json"
    broken.write_text(json.dumps(matrix), encoding="utf-8")

    code = command.main(
        ["--mold", "secret-02", "--output", str(tmp_path / "out")],
        root=tmp_path,
        matrix_path=broken,
    )

    assert code == 2
    saved = json.loads((tmp_path / "out" / "benchmark.json").read_text(encoding="utf-8"))
    assert saved["status"] == "incomplete"
    assert {cell["outcome"] for cell in saved["cells"] if cell["kind"] == "target"} == {"pending"}


def test_broken_control_in_the_target_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    targets = tmp_path / "targets"
    shutil.copytree(runner.PACKAGE / "targets", targets)
    domain = targets / "domain.py"
    text = domain.read_text(encoding="utf-8")
    disabled = 'if self.profile.on("output-escaping"):'
    assert disabled in text
    domain.write_text(text.replace(disabled, "if False:"), encoding="utf-8")
    monkeypatch.setattr(runner, "TARGETS_DIR", targets)

    code = command.main(["--mold", "output-01", "--output", str(tmp_path / "out")], root=tmp_path)

    assert code == 1
    saved = json.loads((tmp_path / "out" / "benchmark.json").read_text(encoding="utf-8"))
    failed = {cell["case_id"] for cell in saved["cells"] if cell["outcome"] == "failed"}
    assert "output-01-tools-python-hardened" in failed
    assert "mutation-output-escaping-isolated" in failed
