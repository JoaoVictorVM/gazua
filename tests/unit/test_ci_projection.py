import json

import pytest
from ci_support import plain_run, run_with_baseline

from gazua.ci.projection import ProjectionError, project
from gazua.reports.models import Reproduction

ALLOWED = {
    "id",
    "severity",
    "damage",
    "mode",
    "tool",
    "status",
    "regression",
    "effective_gated",
    "reproduction",
}


def test_projection_keeps_only_allowed_fields() -> None:
    run = plain_run()

    summary = project(run)

    data = summary.model_dump(mode="json")
    assert set(data) == {
        "schema_version",
        "run_id",
        "gazua_version",
        "mode",
        "effective_exit_code",
        "baseline",
        "new_findings",
        "known_findings",
        "not_tested",
        "not_applicable",
        "findings",
        "diagnostics",
    }
    assert all(set(item) == ALLOWED for item in data["findings"])
    text = json.dumps(data)
    for scenario in run.scenarios:
        assert scenario.attack not in text
    assert run.metadata.target_ref not in text
    for proof in run.proofs:
        assert proof.execution_id not in text
    assert "GAZUA-CANARY" not in text


def test_baseline_counts_and_effective_gate_are_preserved() -> None:
    known = project(run_with_baseline("open"))
    regressed = project(run_with_baseline("closed"))
    native = project(plain_run())

    assert (known.new_findings, known.known_findings, known.effective_exit_code) == (0, 1, 0)
    [item] = known.findings
    assert (item.status, item.effective_gated, item.regression) == ("open", False, False)
    [again] = regressed.findings
    assert (again.status, again.effective_gated, again.regression) == ("new", True, True)
    assert regressed.effective_exit_code == 1
    [first] = native.findings
    assert (first.status, first.effective_gated) == (None, True)
    assert (native.new_findings, native.known_findings) == (1, 0)
    assert (native.not_tested, native.not_applicable) == (1, 1)


def test_projection_rejects_inconsistent_comparison() -> None:
    compared = run_with_baseline("open")
    assert compared.baseline is not None
    broken = compared.model_copy(
        update={"baseline": compared.baseline.model_copy(update={"entries": []})}
    )

    with pytest.raises(ProjectionError) as caught:
        project(broken)

    assert caught.value.code == "ci_projection_invalid"


@pytest.mark.parametrize(
    "argv",
    [
        ["gazua", "run", "--tools", "--mold", "idor-01\n--evil"],
        ["gazua", "run", "--tools", "--mold", "a b"],
        ["gazua", "run", "--tools", "--mold", "\x1b]52;c;aGk=\x07"],
        ["gazua", "run", "--tools", "--mold", "`whoami`"],
        ["gazua", "run", "--tools", "--key", "sk-" + "a" * 30],
        ["rm", "-rf", "/"],
        ["gazua", "run", "--agent", "--mold", "idor-01"],
    ],
)
def test_reproduction_tokens_are_sanitized(argv: list[str]) -> None:
    run = plain_run()
    [finding] = run.findings
    changed = finding.model_copy(update={"reproduction": Reproduction(argv=argv, available=True)})
    hostile = run.model_copy(update={"findings": [changed]})

    summary = project(hostile)

    [item] = summary.findings
    assert item.reproduction is None
    assert summary.diagnostics == ["ci_reproduction_omitted"]


@pytest.mark.parametrize(
    "name", ["get order", "a|b", "<img src=x>", "x\x1b[31m", "ghp_" + "a" * 36, "x" * 201]
)
def test_hostile_tool_names_are_omitted(name: str) -> None:
    run = plain_run()
    [finding] = run.findings
    hostile = run.model_copy(update={"findings": [finding.model_copy(update={"tool_name": name})]})

    summary = project(hostile)

    assert summary.findings[0].tool is None
    assert "ci_tool_name_omitted" in summary.diagnostics


def test_verification_runs_are_not_projected() -> None:
    from gazua.baseline.models import VerificationResult

    run = plain_run()
    verification = VerificationResult.model_construct(outcome="interrupted")

    with pytest.raises(ProjectionError):
        project(run.model_copy(update={"verification": verification}))
