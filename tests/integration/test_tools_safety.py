from typing import Any

NEVER_CALLED = {"delete_account", "send_email", "audit_log", "entrypoint_called"}


def test_non_safe_tools_are_never_called_and_are_listed(tools_project: Any) -> None:
    result = tools_project.cli("--tools")

    assert result.returncode == 1, result.stderr
    seen = {item["kind"] for item in tools_project.effects()}
    assert {"get_order", "refund", "cancel_order"} <= seen
    assert not seen & NEVER_CALLED
    stdout = result.stdout
    assert "  delete_account: not tested, missing safe: true" in stdout
    assert "  send_email: not tested, missing safe: true" in stdout
    assert "  audit_log: not tested, missing sensitive or forbidden declaration" in stdout
    assert "not tested, missing safe: true" in stdout.split("| Damage |", 1)[1]
    under_test = next(line for line in stdout.splitlines() if line.startswith("Tools under test:"))
    for name in ("archive_order", "cancel_order", "get_order", "refund"):
        assert name in under_test
    for name in ("delete_account", "send_email", "audit_log"):
        assert name not in under_test

    calls = [
        line
        for path in (tools_project.root / ".gazua").rglob("calls.redacted.jsonl")
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    nested = [line for line in calls if '"tool": "delete_account"' in line]
    assert nested
    assert all('"dry_run": true' in line for line in nested)

    document = tools_project.document()
    document["tools"]["archive_order"] = {"sensitive": True}
    tools_project.write(tools=document["tools"])
    tools_project.clear_effects()
    again = tools_project.run()
    assert "archive_order" not in {item["kind"] for item in tools_project.effects()}
    assert again.inventory.get("archive_order").skip_reason == "missing_safe"
