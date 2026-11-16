from issue_support import (
    ATTACK_MARK,
    EMAIL,
    OPT_IN,
    PAYLOAD_MARK,
    PRIVATE,
    SECRET,
    planted,
    two_scenarios,
)
from report_factory import FOUND, document

from gazua.issues.rendering import render_issue, render_issues
from gazua.reports.fixes import guide_for


def test_default_issue_has_no_attack_or_conversation() -> None:
    built = planted()
    [issue] = render_issues(built)

    for marker in (*PRIVATE, *OPT_IN, SECRET, EMAIL):
        assert marker not in issue.content, marker
    assert "## Attack" not in issue.content
    assert "proof\\-000001" in issue.content
    assert "source tool\\_return" in issue.content
    assert issue.content.startswith("# High\\: Records of another user\n")


def test_opt_in_includes_only_scenario_attack() -> None:
    built = planted()
    [issue] = render_issues(built, include_attack=True)

    assert ATTACK_MARK in issue.content
    assert PAYLOAD_MARK in issue.content
    for marker in (*PRIVATE, SECRET, EMAIL):
        assert marker not in issue.content, marker
    assert "[redacted-secret]" in issue.content
    assert "untrusted content" in issue.content
    attack_part = issue.content.split("## Attack")[1]
    assert attack_part.count(ATTACK_MARK) == 1
    assert issue.content.index(ATTACK_MARK) > issue.content.index("## Attack")


def test_acceptance_criteria_and_verify_command() -> None:
    built = document()
    [finding] = built.findings
    content = render_issue(built, finding.id)

    criteria = content.split("## Acceptance criteria")[1].split("##")[0]
    expected = guide_for("en").entry("idor_via_agent").acceptance_criteria
    assert criteria.count("- [ ] ") == len(expected)
    assert "- [x]" not in content
    assert f"gazua verify {finding.id} --mode tools" in content
    assert "not met by exporting" in content
    assert "0/5 does not close" in content
    for title in ("Fixes the cause:", "Reduces the risk:", "Does not solve:"):
        assert title in content
    assert "fix\\-idor\\_via\\_agent" in content
    assert "gazua baseline" in content


def test_rates_remain_per_scenario() -> None:
    built = two_scenarios()
    [finding] = built.findings
    content = render_issue(built, finding.id)

    assert len(finding.scenarios) == 2
    lines = [line for line in content.splitlines() if line.startswith("- Scenario ")]
    assert len(lines) == 2
    assert all("1\\/1\\, up to \\~100\\%" in line for line in lines)
    assert "2\\/2" not in content


def test_unavailable_reproduction_is_not_invented() -> None:
    data = planted().model_dump(mode="json")
    reproduction = {"argv": [], "cwd": ".", "available": False, "reason": "custom_target"}
    data["findings"][0]["reproduction"] = reproduction
    for scenario in data["scenarios"]:
        if scenario["attack_key"] == FOUND:
            scenario["reproduction"] = reproduction
    from gazua.reports.models import RunDocument

    built = RunDocument.model_validate(data)
    content = render_issue(built, built.findings[0].id)

    assert "No reproduction command is available \\(custom target\\)" in content
    assert "gazua run" not in content
    available = render_issue(document(), document().findings[0].id)
    assert "available in that local report" in available
    assert "gazua run" not in available


def test_rendering_is_deterministic() -> None:
    built = planted()

    assert render_issues(built) == render_issues(built)
    assert render_issues(built, include_attack=True) == render_issues(built, include_attack=True)
