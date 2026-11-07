import re
from pathlib import Path

import pytest

PUBLIC_DOCUMENTS = ("README.md", "SECURITY.md", "docs/releasing.md")
PLANNING_REFERENCE = re.compile(r"\b(PRD|F\d{2})\b|\.planning|\.harness|spec\.md|plan\.md")


def read(project_root: Path, name: str) -> str:
    return (project_root / name).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "statement",
    [
        "Other tools ask whether the model refused; Gazua proves whether the code stops the attack",
        "A user abusing the company",
        "A third party abusing the user through the agent",
        "The agent erring alone",
        "systems you own or have written authorization to test",
        "attack text reaches the model provider",
        "abuse filters",
        "floor, not a ceiling",
        "fixed and attacks are not adaptive",
        "no telemetry",
    ],
)
def test_readme_states_required_positioning_and_limits(project_root: Path, statement: str) -> None:
    assert statement in read(project_root, "README.md")


def test_readme_has_no_comparison_before_a_recorded_experiment(project_root: Path) -> None:
    assert "promptfoo" not in read(project_root, "README.md").lower()


def test_security_policy_describes_private_reporting(project_root: Path) -> None:
    policy = read(project_root, "SECURITY.md")

    assert "/security/advisories/new" in policy
    assert "private" in policy.lower()
    assert "@" not in policy


@pytest.mark.parametrize("name", PUBLIC_DOCUMENTS)
def test_public_documents_do_not_reference_local_planning(project_root: Path, name: str) -> None:
    assert not PLANNING_REFERENCE.search(read(project_root, name))
