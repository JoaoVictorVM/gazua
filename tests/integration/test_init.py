import json
import os
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import typer
from typer.testing import CliRunner

from gazua import cli, project_init
from gazua.config import ToolClass, load_config

Spy = Callable[..., dict[str, Any]]

AGENT = """\
import gazua

def get_order(order_id): ...
def refund_order(order_id): ...
def Send_Email(to): ...
def delete_user(user): ...

async def entrypoint(message): ...

tools = gazua.wrap([get_order, refund_order, Send_Email, delete_user])
"""


def init(console_script: Path, *arguments: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(console_script), "init", *arguments],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        check=False,
    )


def test_init_writes_valid_reviewable_config(console_script: Path, workdir: Path) -> None:
    (workdir / "agent.py").write_text(AGENT, encoding="utf-8")

    result = init(console_script, cwd=workdir)

    assert result.returncode == 0, result.stderr
    loaded = load_config(workdir / "gazua.yaml")
    tools = loaded.config.tools
    assert sorted(tools) == ["Send_Email", "delete_user", "get_order", "refund_order"]
    assert all(tool.safe is False for tool in tools.values())
    assert tools["get_order"].classification is ToolClass.UNCLASSIFIED
    for name in ("refund_order", "Send_Email", "delete_user"):
        assert tools[name].classification is ToolClass.SENSITIVE
    assert not any(tool.forbidden for tool in tools.values())
    assert loaded.config.entrypoint == "agent:entrypoint"

    text = (workdir / "gazua.yaml").read_text(encoding="utf-8")
    assert text.count("REVIEW REQUIRED") == 5
    assert "yaml-language-server: $schema=https://" in text
    assert "safe: true" not in text
    assert (workdir / ".gitignore").read_bytes() == b".gazua/\n"

    assert "get_order" in result.stdout
    assert "sensitive" in result.stdout
    assert "execute code" in result.stderr


def test_init_output_never_shows_source_or_literals(console_script: Path, workdir: Path) -> None:
    (workdir / "agent.py").write_text(
        "import gazua\n"
        "VALUE = 'sentinel-private-value'\n"
        "@gazua.tool\n"
        "def a():\n"
        "    return 'sentinel-private-value'\n",
        encoding="utf-8",
    )

    result = init(console_script, cwd=workdir)

    assert result.returncode == 0
    assert "sentinel-private-value" not in result.stdout + result.stderr
    assert "sentinel-private-value" not in (workdir / "gazua.yaml").read_text(encoding="utf-8")


def test_init_accepts_directory_and_entrypoint_without_importing(
    console_script: Path, workdir: Path
) -> None:
    project = workdir / "project"
    project.mkdir()

    result = init(console_script, str(project), "--entrypoint", "absent.module:run", cwd=workdir)

    assert result.returncode == 0, result.stderr
    assert load_config(project / "gazua.yaml").config.entrypoint == "absent.module:run"
    assert not (workdir / "gazua.yaml").exists()


@pytest.mark.parametrize("reference", ["module", "a b:c", "os.system('x'):y", "a:b:c"])
def test_init_rejects_invalid_entrypoint_before_writing(
    console_script: Path, workdir: Path, reference: str
) -> None:
    result = init(console_script, "--entrypoint", reference, cwd=workdir)

    assert result.returncode == 2
    assert "entrypoint" in result.stderr
    assert "Traceback" not in result.stderr
    assert list(workdir.iterdir()) == []


def test_init_on_missing_directory_fails_cleanly(console_script: Path, workdir: Path) -> None:
    result = init(console_script, "absent", cwd=workdir)

    assert result.returncode == 2
    assert "does not exist" in result.stderr
    assert "Traceback" not in result.stderr
    assert list(workdir.iterdir()) == []


def test_init_preserves_existing_config_and_gitignore(console_script: Path, workdir: Path) -> None:
    config = workdir / "gazua.yaml"
    config.write_bytes(b"# mine\r\nnot: valid: yaml\r\n")
    gitignore = workdir / ".gitignore"
    gitignore.write_bytes(b"# mine\n")

    result = init(console_script, cwd=workdir)

    assert result.returncode == 2
    assert "already exists" in result.stderr
    assert config.read_bytes() == b"# mine\r\nnot: valid: yaml\r\n"
    assert gitignore.read_bytes() == b"# mine\n"


def test_second_init_keeps_generated_files(console_script: Path, workdir: Path) -> None:
    assert init(console_script, cwd=workdir).returncode == 0
    before = (workdir / "gazua.yaml").read_bytes(), (workdir / ".gitignore").read_bytes()

    assert init(console_script, cwd=workdir).returncode == 2

    assert before == ((workdir / "gazua.yaml").read_bytes(), (workdir / ".gitignore").read_bytes())


def test_init_does_not_write_through_a_config_symlink(console_script: Path, workdir: Path) -> None:
    project = workdir / "project"
    project.mkdir()
    pointed = workdir / "elsewhere.yaml"
    try:
        os.symlink(pointed, project / "gazua.yaml")
    except OSError:
        pytest.skip("this system does not allow creating symlinks")

    result = init(console_script, str(project), cwd=workdir)

    assert result.returncode == 2
    assert not pointed.exists()
    assert (project / "gazua.yaml").is_symlink()


def test_concurrent_config_creation_is_not_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_plan = project_init._plan_gitignore

    def create_config_first(root: Path):
        (root / "gazua.yaml").write_text("# concurrent\n", encoding="utf-8")
        return real_plan(root)

    monkeypatch.setattr(project_init, "_plan_gitignore", create_config_first)

    result = CliRunner().invoke(cli.app, ["init", str(tmp_path)])

    assert result.exit_code == 2
    assert (tmp_path / "gazua.yaml").read_text(encoding="utf-8") == "# concurrent\n"
    assert not (tmp_path / ".gitignore").exists()


@pytest.mark.parametrize(
    ("before", "after"),
    [
        (None, b".gazua/\n"),
        (b"", b".gazua/\n"),
        (b"# comment\n*.pyc\n", b"# comment\n*.pyc\n.gazua/\n"),
        (b"*.pyc", b"*.pyc\n.gazua/\n"),
        (b"# comment\r\n*.pyc\r\n", b"# comment\r\n*.pyc\r\n.gazua/\r\n"),
        (b"*.pyc\r\nbuild", b"*.pyc\r\nbuild\r\n.gazua/\r\n"),
        (b".gazua/\n", b".gazua/\n"),
        (b"/.gazua/\n", b"/.gazua/\n"),
        (b".gazua\r\n", b".gazua\r\n"),
        (b".gazua/   \n", b".gazua/   \n"),
        (b"\xef\xbb\xbf.gazua/\n", b"\xef\xbb\xbf.gazua/\n"),
        (b"#.gazua/\n", b"#.gazua/\n.gazua/\n"),
        (b".gazua/\n!.gazua/\n", b".gazua/\n!.gazua/\n.gazua/\n"),
        (b".gazua/\n!.gazua/keep\n", b".gazua/\n!.gazua/keep\n.gazua/\n"),
        (b"!.gazua/\n.gazua/\n", b"!.gazua/\n.gazua/\n"),
        (b"caf\xe9\n", b"caf\xe9\n.gazua/\n"),
    ],
    ids=[
        "absent",
        "empty",
        "comments",
        "no-final-newline",
        "crlf",
        "crlf-no-final-newline",
        "present",
        "anchored",
        "crlf-no-slash",
        "trailing-spaces",
        "bom",
        "commented-out",
        "negated",
        "negated-content",
        "negation-overridden",
        "not-utf8",
    ],
)
def test_gitignore_update_is_idempotent(tmp_path: Path, before: bytes | None, after: bytes) -> None:
    gitignore = tmp_path / ".gitignore"
    if before is not None:
        gitignore.write_bytes(before)

    result = project_init.initialize_project(tmp_path)

    assert gitignore.read_bytes() == after
    assert result.gitignore_changed is (before != after)
    assert sorted(path.name for path in tmp_path.iterdir()) == [".gitignore", "gazua.yaml"]

    (tmp_path / "gazua.yaml").unlink()
    project_init.initialize_project(tmp_path)
    assert gitignore.read_bytes() == after


def test_reinclude_rule_produces_a_warning(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_bytes(b".gazua/\n!.gazua/\n")

    result = project_init.initialize_project(tmp_path)

    assert "gitignore_reinclude" in [item.code for item in result.warnings]


def test_existing_gitignore_mode_is_preserved(tmp_path: Path) -> None:
    gitignore = tmp_path / ".gitignore"
    gitignore.write_bytes(b"*.pyc\n")
    gitignore.chmod(0o644)
    mode = gitignore.stat().st_mode

    project_init.initialize_project(tmp_path)

    assert gitignore.stat().st_mode == mode


def test_gitignore_symlink_stops_before_any_write(tmp_path: Path) -> None:
    pointed = tmp_path / "pointed"
    pointed.write_bytes(b"x\n")
    project = tmp_path / "project"
    project.mkdir()
    try:
        os.symlink(pointed, project / ".gitignore")
    except OSError:
        pytest.skip("this system does not allow creating symlinks")

    result = CliRunner().invoke(cli.app, ["init", str(project)])

    assert result.exit_code == 2
    assert not (project / "gazua.yaml").exists()
    assert pointed.read_bytes() == b"x\n"


def test_init_reports_partial_write_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gitignore = tmp_path / ".gitignore"
    gitignore.write_bytes(b"# mine\n")

    def fail_replace(*_arguments: object) -> None:
        raise PermissionError(13, "Access denied")

    monkeypatch.setattr(project_init.os, "replace", fail_replace)

    result = CliRunner().invoke(cli.app, ["init", str(tmp_path)])

    assert result.exit_code == 2
    assert "Created gazua.yaml" in result.stderr
    assert "Add .gazua/" in result.stderr
    assert "Access denied" in result.stderr
    assert "Traceback" not in result.stderr
    assert (tmp_path / "gazua.yaml").exists()
    assert gitignore.read_bytes() == b"# mine\n"
    assert sorted(path.name for path in tmp_path.iterdir()) == [".gitignore", "gazua.yaml"]


def test_concurrent_gitignore_change_is_not_lost(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gitignore = tmp_path / ".gitignore"
    gitignore.write_bytes(b"# mine\n")
    real_write = project_init._write_config

    def change_during_write(path: Path, content: str) -> None:
        real_write(path, content)
        gitignore.write_bytes(b"# someone else\n")

    monkeypatch.setattr(project_init, "_write_config", change_during_write)

    result = CliRunner().invoke(cli.app, ["init", str(tmp_path)])

    assert result.exit_code == 2
    assert "changed while" in result.stderr
    assert gitignore.read_bytes() == b"# someone else\n"
    assert sorted(path.name for path in tmp_path.iterdir()) == [".gitignore", "gazua.yaml"]


def test_init_without_tools_or_entrypoint_is_actionable(
    console_script: Path, workdir: Path
) -> None:
    result = init(console_script, cwd=workdir)

    assert result.returncode == 0
    config = load_config(workdir / "gazua.yaml").config
    assert config.tools == {}
    assert config.entrypoint is None
    assert "not ready to run" in result.stdout
    assert "entrypoint" in result.stdout
    assert "tools" in result.stdout


def test_ready_summary_makes_no_verification_claim(console_script: Path, workdir: Path) -> None:
    (workdir / "agent.py").write_text(AGENT, encoding="utf-8")

    result = init(console_script, cwd=workdir)

    assert "not ready to run" not in result.stdout
    assert "not imported" in result.stdout


def test_incomplete_discovery_is_highlighted(console_script: Path, workdir: Path) -> None:
    (workdir / "bad.py").write_text("def broken(:\n", encoding="utf-8")
    (workdir / "good.py").write_text("import gazua\n@gazua.tool\ndef ok(): ...\n", encoding="utf-8")

    result = init(console_script, cwd=workdir)

    assert result.returncode == 0
    assert "bad.py:1" in result.stderr
    assert "incomplete" in result.stdout
    text = (workdir / "gazua.yaml").read_text(encoding="utf-8")
    assert "discovery was incomplete" in text
    assert "ok" in load_config(workdir / "gazua.yaml").config.tools


def test_tool_names_that_look_like_yaml_values_stay_strings(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "import gazua\n"
        "@gazua.tool\ndef null(): ...\n"
        "@gazua.tool\ndef on(): ...\n"
        "@gazua.tool\ndef ação(): ...\n",
        encoding="utf-8",
    )

    project_init.initialize_project(tmp_path)

    assert sorted(load_config(tmp_path / "gazua.yaml").config.tools) == sorted(
        ["null", "on", "ação"]
    )


def test_init_and_loading_access_no_credentials_or_network(run_spied: Spy, workdir: Path) -> None:
    (workdir / "agent.py").write_text(AGENT, encoding="utf-8")
    (workdir / ".env").write_text("OPENAI_API_KEY=sentinel-not-a-real-key\n", encoding="utf-8")

    control = run_spied("control")
    assert control["network"]
    assert control["credential_reads"]

    created = run_spied("cli", "init")
    assert created["exit_code"] == 0
    loaded = run_spied("load", "gazua.yaml")
    assert loaded["exit_code"] == 0

    for report in (created, loaded):
        assert report["network"] == []
        assert report["credential_reads"] == []
        assert report["environment_listed"] is False
        assert all(Path(path).name != ".env" for path in report["opened_paths"])
    assert any(path.endswith("agent.py") for path in created["opened_paths"])


def test_invalid_field_exits_2_and_names_file_line_and_field(tmp_path: Path) -> None:
    config = tmp_path / "gazua.yaml"
    config.write_text("schema_version: 1\nlimits:\n  max_runs: -3\n", encoding="utf-8")
    probe = typer.Typer()

    # No shipped command loads an existing file yet, so the shared adapter is driven directly.
    @probe.command()
    def load() -> None:
        with cli.exit_on_config_error():
            load_config(config)

    result = CliRunner().invoke(probe, [])

    assert result.exit_code == 2
    assert f"{config}:3:13: limits.max_runs: Expected an integer greater than zero." in (
        result.stderr
    )
    assert "Traceback" not in result.stderr
    assert "-3" not in result.stderr.replace(str(config), "")


def test_generated_config_has_only_declared_fields(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(AGENT, encoding="utf-8")

    project_init.initialize_project(tmp_path)

    document = load_config(tmp_path / "gazua.yaml").config.to_document()
    assert json.loads(json.dumps(document)) == {
        "schema_version": 1,
        "entrypoint": "agent:entrypoint",
        "tools": {
            "Send_Email": {"safe": False, "sensitive": True},
            "delete_user": {"safe": False, "sensitive": True},
            "get_order": {"safe": False},
            "refund_order": {"safe": False, "sensitive": True},
        },
    }
