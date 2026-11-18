import json
import os
from pathlib import Path

from mcp_support import McpProject

PRIVATE_ARGUMENT = "private-launch-argument-7731"
PROVIDER_KEY = "sk-provider-key-for-test-only-9921"


def test_canary_secrets_absent_from_public_outputs(tmp_path: Path) -> None:
    project = McpProject(tmp_path / "project")
    server = dict(project.config["mcp"])
    # The raw server ignores extra arguments; this one stands for a token in a launch line.
    server["args"] = [*server["args"], PRIVATE_ARGUMENT]
    project.update(mcp=server)
    environment = {**os.environ, "OPENAI_API_KEY": PROVIDER_KEY, "GAZUA_PRIVATE": "x"}

    result = project.cli("run", "--tools", "--mold", "idor-01", env=environment)

    assert result.returncode == 1, result.stderr
    public = [result.stdout, result.stderr]
    for name in ("run.json", "report.md", "report.html"):
        public.append((project.root / ".gazua" / name).read_text(encoding="utf-8"))
    for text in public:
        assert PRIVATE_ARGUMENT not in text
        assert PROVIDER_KEY not in text
        assert "scenario.json" not in text


def test_no_provider_keys_or_external_fetches(tmp_path: Path) -> None:
    project = McpProject(tmp_path / "project")
    project.scenario["environment_file"] = str(project.state / "environment.json")
    project.save_scenario()
    environment = {
        **os.environ,
        "OPENAI_API_KEY": PROVIDER_KEY,
        "ANTHROPIC_API_KEY": PROVIDER_KEY,
        "GAZUA_SESSION": "elsewhere",
    }

    result = project.cli("run", "--tools", "--mold", "idor-01", env=environment)

    assert result.returncode == 1, result.stderr
    names = json.loads((project.state / "environment.json").read_text(encoding="utf-8"))
    assert "OPENAI_API_KEY" not in names
    assert "ANTHROPIC_API_KEY" not in names
    assert not [name for name in names if name.upper().startswith("GAZUA")]
