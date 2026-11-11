import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from gazua import cli
from gazua.catalog.listing import NO_CONFIG_NOTE
from gazua.catalog.loader import EXTERNAL_WARNING

MoldFactory = Callable[..., dict[str, Any]]
Spy = Callable[..., dict[str, Any]]

SENTINEL_MODULE = """\
from pathlib import Path
Path("SENTINEL-IMPORTED").write_text("imported", encoding="utf-8")
def entrypoint(): ...
def reset(): ...
def sink(value): ...
"""
TARGET_CONFIG = """\
schema_version: 1
entrypoint: sentinel_target:entrypoint
target: {reset: sentinel_target:reset}
output_sink: sentinel_target:sink
tools:
  get_order: {safe: true, sensitive: false, owner_arg: user_id, actor_arg: actor_id}
fixtures:
  attacker: {id: GAZUA-attacker}
  victim:
    id: GAZUA-victim
    records: [{tool: get_order, id_arg: order_id, id: 1}]
molds:
  directories: [molds]
"""


def invoke(*arguments: str):
    return CliRunner().invoke(cli.app, ["run", *arguments])


def agent_document(mold: MoldFactory, identifier: str) -> dict[str, Any]:
    return mold(
        id=identifier,
        entry="web_page",
        supported_modes=["agent"],
        action={"kind": "inject_text"},
    )


def mold_lines(output: str) -> list[str]:
    return [line.split()[0] for line in output.splitlines() if line.startswith("    ")]


def test_list_groups_and_filters_without_executing_target(
    tmp_path: Path,
    mold: MoldFactory,
    console_script: Path,
    clean_environment: Callable[[], dict[str, str]],
) -> None:
    (tmp_path / "sentinel_target.py").write_text(SENTINEL_MODULE, encoding="utf-8")
    (tmp_path / "gazua.yaml").write_text(TARGET_CONFIG, encoding="utf-8")
    (tmp_path / "molds").mkdir()
    (tmp_path / "molds" / "web.yaml").write_text(
        json.dumps(agent_document(mold, "custom-web")), encoding="utf-8"
    )

    def run(*arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(console_script), "run", "--list", *arguments],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env={**clean_environment(), "PYTHONIOENCODING": "utf-8"},
            timeout=60,
            check=False,
        )

    everything = run()
    again = run()
    tools_only = run("--mode", "tools")
    agent_only = run("--mode", "agent")
    in_portuguese = run("--mode", "tools", "--language", "pt")

    assert everything.returncode == 0, everything.stderr
    assert everything.stdout == again.stdout
    assert not (tmp_path / "SENTINEL-IMPORTED").exists()
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "gazua.yaml",
        "molds",
        "sentinel_target.py",
    ]

    listed = mold_lines(everything.stdout)
    assert listed.index("permission-01") < listed.index("secret-01") < listed.index("idor-01")
    assert listed.index("idor-01") < listed.index("custom-web") < listed.index("output-01")
    assert "custom-web" not in mold_lines(tools_only.stdout)
    assert mold_lines(agent_only.stdout) == ["custom-web"]
    assert mold_lines(in_portuguese.stdout) == mold_lines(tools_only.stdout)
    assert "Permissão só no prompt" in in_portuguese.stdout

    idor_line = next(line for line in everything.stdout.splitlines() if "idor-01 " in line)
    assert "eligible_by_config" in idor_line
    web_line = next(line for line in everything.stdout.splitlines() if "custom-web" in line)
    assert "custom:molds" in web_line
    assert "entry adapter not verified" in web_line
    permission_line = next(
        line for line in everything.stdout.splitlines() if "permission-01 " in line
    )
    assert "missing_declarations" in permission_line
    assert "tool.forbidden" in permission_line
    assert "As GAZUA-attacker" not in everything.stdout
    assert "${" not in everything.stdout
    assert "resisted" not in everything.stdout


def test_list_external_warning_and_partial_error_exit(
    tmp_path: Path, mold: MoldFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "good.yaml").write_text(json.dumps(mold(id="vendor-good")), encoding="utf-8")
    (vendor / "bad.yaml").write_text(json.dumps(mold(id="vendor-bad", target="x")), "utf-8")
    (tmp_path / "gazua.yaml").write_text(
        "schema_version: 1\nmolds: {external_catalogs: [vendor]}\n", encoding="utf-8"
    )

    result = invoke("--list")

    assert result.exit_code == 2
    assert "vendor-good" in mold_lines(result.stdout)
    assert "vendor-bad" not in result.stdout
    errors = result.stderr.splitlines()
    assert errors[0] == EXTERNAL_WARNING.format(path="vendor")
    assert any(line.startswith("invalid mold vendor-bad: ") and "target" in line for line in errors)


def test_list_without_config_and_with_explicit_missing_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    default = invoke("--list")
    explicit = invoke("--list", "--config", "missing.yaml")
    (tmp_path / "broken.yaml").write_text(
        "schema_version: 1\nmolds: {external_catalogs: [vendor]}\nlimits: {max_runs: 0}\n",
        encoding="utf-8",
    )
    invalid = invoke("--list", "--config", "broken.yaml")

    assert default.exit_code == 0, default.stderr
    assert NO_CONFIG_NOTE in default.stdout
    assert len(mold_lines(default.stdout)) == 15
    assert explicit.exit_code == 2
    assert "missing.yaml" in explicit.stderr
    assert mold_lines(explicit.stdout) == []
    assert invalid.exit_code == 2
    assert "limits.max_runs" in invalid.stderr
    assert "Warning: loading external" not in invalid.stderr
    assert list(tmp_path.iterdir()) == [tmp_path / "broken.yaml"]


def test_list_reads_config_relative_to_its_folder(
    tmp_path: Path, mold: MoldFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    (project / "molds").mkdir(parents=True)
    (project / "molds" / "m.yaml").write_text(json.dumps(mold(id="relative-a")), "utf-8")
    (project / "gazua.yaml").write_text(
        "schema_version: 1\nmolds: {directories: [molds]}\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)

    result = invoke("--list", "--config", str(project / "gazua.yaml"))

    assert result.exit_code == 0, result.stderr
    assert "relative-a" in mold_lines(result.stdout)


def test_catalog_load_and_list_do_not_read_credentials_or_use_network(run_spied: Spy) -> None:
    control = run_spied("control")
    report = run_spied("cli", "run", "--list")

    assert control["network"]
    assert control["credential_reads"]
    assert report["exit_code"] == 0
    assert report["network"] == []
    assert report["credential_reads"] == []
    assert report["environment_listed"] is False


def test_run_without_list_is_actionable_until_engine_exists(
    console_script: Path, workdir: Path
) -> None:
    result = subprocess.run(
        [str(console_script), "run"],
        cwd=workdir,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    flags = subprocess.run(
        [sys.executable, "-m", "gazua", "run", "--help"],
        cwd=workdir,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert "use gazua run --list" in result.stderr
    assert "Traceback" not in result.stderr
    assert list(workdir.iterdir()) == []
    assert "--list" in flags.stdout
    assert "--tools" in flags.stdout
    assert "--agent" not in flags.stdout
