import hashlib
import json

from hypothesis import given
from hypothesis import strategies as st
from report_factory import FOUND, TARGET, document, five_states
from verdict_factory import context

from gazua.reports.builder import finding_id

TEXT = st.text(min_size=1, max_size=40)


def test_finding_id_survives_run_model_fixture_and_directory_changes() -> None:
    first = document(target=TARGET)
    again = document(target=TARGET)
    expected = (
        "finding-"
        + hashlib.sha256(
            json.dumps([TARGET, "tools", "idor-02", "get_order"], separators=(",", ":")).encode()
        ).hexdigest()
    )

    assert first.findings[0].id == again.findings[0].id == expected
    assert (
        finding_id(TARGET, "tools", "idor-02", None)
        == "finding-"
        + hashlib.sha256(b'["tools_target:entrypoint","tools","idor-02",null]').hexdigest()
    )


@given(TEXT, TEXT, st.sampled_from(["tools", "agent"]), st.one_of(st.none(), TEXT))
def test_tool_mold_mode_or_target_change_id(
    target: str, mold: str, mode: str, tool: str | None
) -> None:
    base = finding_id(target, mode, mold, tool)  # type: ignore[arg-type]

    assert base.startswith("finding-")
    assert len(base) == len("finding-") + 64
    assert finding_id(target + "x", mode, mold, tool) != base  # type: ignore[arg-type]
    assert finding_id(target, mode, mold + "x", tool) != base  # type: ignore[arg-type]
    other_mode = "agent" if mode == "tools" else "tools"
    assert finding_id(target, other_mode, mold, tool) != base
    assert finding_id(target, mode, mold, (tool or "") + "x") != base  # type: ignore[arg-type]


def test_fixture_rates_remain_separate() -> None:
    second = context("victim_record_access", "tools", key="tools:idor-02:second-record")
    built = document(five_states(extra_found=[second]))

    assert len(built.findings) == 1
    finding = built.findings[0]
    assert finding.scenarios == [FOUND, "tools:idor-02:second-record"]
    rates = {
        item.attack_key: (item.rate, item.upper_bound, item.evaluated)
        for item in built.verdicts.results
        if item.attack_key in finding.scenarios
    }
    assert all(evaluated == 1 for _, _, evaluated in rates.values())
    assert len(rates) == 2


def test_low_grouping_preserves_ids_proofs_and_gate() -> None:
    from gazua.reports.rendering import build_view, presentation_groups, render_report

    built = document()
    finding = built.findings[0]
    lows = [
        finding.model_copy(update={"id": f"finding-{str(number) * 64}", "severity": "low"})
        for number in (1, 2)
    ]
    view = build_view(built)
    template = view.findings[0]
    views = [
        type(template)(item, template.scenarios, template.proofs, template.commands)
        for item in lows
    ]

    groups = presentation_groups([view.findings[0], *views])

    assert groups[0] is view.findings[0]
    group = groups[1]
    assert [item.finding.id for item in group.findings] == [item.id for item in lows]
    assert all(item.proofs == template.proofs for item in group.findings)
    assert group.gated == any(item.gated for item in lows)
    assert len(built.verdicts.results) == 5
    html, markdown = render_report(built)
    assert finding.id in html
    assert finding.id in markdown
