import json
import random

from ci_support import plain_run
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from gazua.ci.comment import render_comment
from gazua.ci.models import CiSummary
from gazua.ci.projection import comment_document, project
from gazua.ci.sarif import build_sarif, sarif_json
from gazua.reports.models import Reproduction

RUN = plain_run()
HOSTILE = st.text(min_size=1, max_size=80).filter(lambda value: len(value.strip()) > 3)


def _outputs(summary: CiSummary) -> str:
    comment = render_comment(comment_document(summary))
    return comment + sarif_json(build_sarif(summary)) + summary.model_dump_json()


@settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
@given(attack=HOSTILE, tool=HOSTILE, token=HOSTILE)
def test_arbitrary_adversarial_text_never_reaches_ci_outputs(
    attack: str, tool: str, token: str
) -> None:
    marker = "ZQX" + attack
    [finding] = RUN.findings
    scenarios = [
        item.model_copy(update={"attack": marker, "payload": {"text": marker}})
        for item in RUN.scenarios
    ]
    hostile_tool = "ZQX" + tool + " "
    command = Reproduction(
        argv=["gazua", "run", "--tools", "--mold", "ZQX" + token + " "], available=True
    )
    changed = finding.model_copy(
        update={"attack": marker, "tool_name": hostile_tool, "reproduction": command}
    )
    run = RUN.model_copy(update={"scenarios": scenarios, "findings": [changed]})

    text = _outputs(project(run))

    assert marker not in text
    assert json.dumps(marker)[1:-1] not in text
    assert hostile_tool not in text
    assert "ZQX" not in text


@given(st.integers(min_value=0, max_value=3))
def test_comment_and_sarif_are_deterministic(seed: int) -> None:
    first = _outputs(project(RUN))
    second = _outputs(project(RUN.model_copy()))

    assert first == second
    assert seed >= 0


@given(st.randoms())
def test_finding_order_does_not_change_counts(generator: random.Random) -> None:
    summary = project(RUN)
    template = summary.findings[0]
    severities = ["critical", "high", "medium", "low"]
    findings = [
        template.model_copy(
            update={"id": "finding-" + f"{index:064x}", "severity": severities[index % 4]}
        )
        for index in range(1, 9)
    ]
    shuffled = list(findings)
    generator.shuffle(shuffled)
    rank = {name: index for index, name in enumerate(severities)}
    ordered = sorted(shuffled, key=lambda item: (rank[item.severity], item.id))

    a = summary.model_copy(update={"findings": ordered, "new_findings": 8})
    b = summary.model_copy(
        update={
            "findings": sorted(findings, key=lambda item: (rank[item.severity], item.id)),
            "new_findings": 8,
        }
    )

    assert _outputs(a) == _outputs(b)
    assert comment_document(a).counts == comment_document(b).counts
