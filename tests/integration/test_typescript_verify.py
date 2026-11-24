from pathlib import Path

from typescript_support import TypeScriptProject, require_typescript
from verify_support import accepted, baseline_document, gazua, latest_run


def test_replay_requires_same_adapter_module_and_sdk_contract(tmp_path: Path) -> None:
    require_typescript()
    project = TypeScriptProject(tmp_path / "project")
    project.write(legit_tasks=[])
    (project.root / ".gitignore").write_text(".gazua/\n", encoding="utf-8")
    accepted(project.root, "--agent", "--mold", "secret-04")
    module = project.root / "dist" / "agent.js"
    original = module.read_bytes()
    project.behave("hardened")

    # A rebuilt module is another program: a quiet replay proves nothing about the finding.
    module.write_bytes(original + b"\n// rebuilt\n")
    changed = gazua(project.root, "verify", "secret-04", "--mode", "agent")
    assert changed.returncode == 2, changed.stdout + changed.stderr
    assert "cannot close" in changed.stderr
    [entry] = baseline_document(project.root)["entries"]
    assert entry["status"] == "open"
    assert latest_run(project.root)["verification"]["outcome"] == "incomplete"

    module.write_bytes(original)
    verified = gazua(project.root, "verify", "secret-04", "--mode", "agent")
    assert verified.returncode == 0, verified.stdout + verified.stderr
    assert "closed" in verified.stdout
    run = latest_run(project.root)
    assert run["target_adapter"] == "typescript"
    assert run["typescript"]["module_sha256"]
    [closed] = baseline_document(project.root)["entries"]
    assert closed["status"] == "closed"
