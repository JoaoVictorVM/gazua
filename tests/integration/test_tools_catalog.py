import json
from collections.abc import Callable
from typing import Any


def test_only_tools_molds_run_including_custom(
    tools_project: Any, mold: Callable[..., dict[str, Any]]
) -> None:
    folder = tools_project.root / "molds"
    folder.mkdir()
    (folder / "custom-idor.yaml").write_text(json.dumps(mold()), encoding="utf-8")
    agent_only = mold(
        id="custom-agent",
        supported_modes=["agent"],
        action={"kind": "inject_text"},
        success={"signal": "victim_record_access"},
    )
    (folder / "custom-agent.yaml").write_text(json.dumps(agent_only), encoding="utf-8")
    tools_project.write(molds={"directories": ["molds"]})

    result = tools_project.run()
    command = tools_project.cli("--tools", "--mold", "custom-idor")

    molds = {context.mold.id for context in result.contexts}
    assert "custom-idor" in molds
    assert "custom-agent" not in molds
    assert all("tools" in context.mold.supported_modes for context in result.contexts)
    [custom] = [item for item in result.verdicts.results if item.mold_id == "custom-idor"]
    assert custom.state == "finding"
    assert command.returncode == 1
    assert "Mold: custom-idor." in command.stdout
    agent = tools_project.cli("--tools", "--mold", "custom-agent")
    assert agent.returncode == 2

    tools_project.clear_effects()
    (folder / "broken.yaml").write_text("schema_version: 1\nid: Not Valid\n", encoding="utf-8")
    broken = tools_project.cli("--tools")
    assert broken.returncode == 2
    assert "broken.yaml" in broken.stderr
    assert not (tools_project.root / "effects").exists()
