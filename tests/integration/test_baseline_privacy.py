from pathlib import Path

from report_support import echo_project, gazua, local_environment

SECRET = "sk-" + "Z" * 32
PERSON = "maria.silva@example.com"


def test_baseline_contains_only_allowlisted_metadata(tmp_path: Path) -> None:
    root = echo_project(tmp_path / "project")
    environment = local_environment(GAZUA_TEST_ECHO=f"{SECRET} {PERSON}")
    first = gazua(root, "run", "--tools", "--mold", "idor-01", env=environment)
    assert first.returncode == 1, first.stderr

    created = gazua(root, "baseline", env=environment)

    assert created.returncode == 0, created.stderr
    text = (root / "gazua-baseline.json").read_text(encoding="utf-8")
    run = (root / ".gazua" / "run.json").read_text(encoding="utf-8")
    forbidden = [
        SECRET,
        PERSON,
        "GAZUA-CANARY-7f3a9c",
        "order-victim-1",
        "attacker-1",
        "victim-1",
        "get_order",
        "echo_target",
        "idor-01",
        "Direct access",
        "gazua run",
        "executions/",
        "payload",
        "attack",
    ]
    for value in forbidden:
        assert value not in text
        assert value not in created.stdout + created.stderr
    allowed = {"schema_version", "gazua_version", "revision", "entries", "id", "mode", "status"}
    allowed |= {"scenarios", "scenario_digest", "language", "verification"}
    import json

    def keys(value: object) -> set[str]:
        if isinstance(value, dict):
            found = set(value)
            for item in value.values():
                found |= keys(item)
            return found
        if isinstance(value, list):
            return set().union(*(keys(item) for item in value)) if value else set()
        return set()

    assert keys(json.loads(text)) <= allowed
    assert "Direct access" in run

    (root / "gazua-baseline.json").write_text(
        f'{{"schema_version": 1, "{SECRET}": "{PERSON}"}}', encoding="utf-8"
    )
    refused = gazua(root, "run", "--tools", env=environment)
    assert refused.returncode == 2
    assert SECRET not in refused.stdout + refused.stderr
    assert PERSON not in refused.stdout + refused.stderr
