from pathlib import Path

from report_support import echo_project, gazua, local_environment

HOSTILE = "evil\x1b]52;c;ZXZpbA==\x07\x1b[2J\x1b]8;;https://evil.example\x1b\\name"


def test_agent_controls_cannot_change_terminal(tmp_path: Path) -> None:
    project = echo_project(tmp_path / "project")
    environment = local_environment(
        GAZUA_TEST_ECHO=f"\x1b[31mred\x1b[0m{HOSTILE}", GAZUA_TEST_TOOL_NAME=HOSTILE
    )

    result = gazua(project, "run", "--tools", env=environment)

    assert result.returncode == 1, result.stderr
    for stream in (result.stdout, result.stderr):
        assert "\x1b" not in stream
        assert "\x9b" not in stream
        assert "\x07" not in stream
        assert "52;c" not in stream
        assert "]8;;" not in stream
    assert "  evil" in result.stdout
    html = (project / ".gazua" / "report.html").read_text(encoding="utf-8")
    markdown = (project / ".gazua" / "report.md").read_text(encoding="utf-8")
    assert "\x1b" not in html
    assert "\x1b" not in markdown
