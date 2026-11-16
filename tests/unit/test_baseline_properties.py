from dataclasses import dataclass

from hypothesis import given
from hypothesis import strategies as st

from gazua.baseline.comparison import compare
from gazua.baseline.models import BaselineDocument, baseline_json
from gazua.baseline.storage import merge_findings, parse_baseline
from gazua.reports.builder import finding_id

HEX = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)
IDS = st.builds(lambda value: "finding-" + value, HEX)
TEXT = st.text(min_size=1, max_size=30)


@dataclass(frozen=True)
class Seen:
    id: str
    gated: bool


def _baseline(ids: list[str], closed: set[str]) -> BaselineDocument:
    entries = [
        {
            "id": item,
            "mode": "tools",
            "status": "closed" if item in closed else "open",
            "scenarios": [{"scenario_digest": "a" * 64, "language": "en"}],
            "verification": {
                "run_id": "GAZUA-run-x",
                "verified_at": "2026-01-01T00:00:00Z",
                "repetitions": 20,
                "scenarios": [{"scenario_digest": "a" * 64, "language": "en"}],
            }
            if item in closed
            else None,
        }
        for item in sorted(set(ids))
    ]
    return BaselineDocument.model_validate(
        {"schema_version": 1, "gazua_version": None, "revision": 1, "entries": entries}
    )


@given(
    st.lists(IDS, max_size=6, unique=True),
    st.lists(st.tuples(IDS, st.booleans()), max_size=6, unique_by=lambda item: item[0]),
    st.data(),
)
def test_comparison_is_pure_and_order_independent(
    accepted: list[str], seen: list[tuple[str, bool]], data: st.DataObject
) -> None:
    closed = set(data.draw(st.lists(st.sampled_from(accepted), unique=True)) if accepted else [])
    known = _baseline(accepted, closed)
    before = baseline_json(known)
    findings = [Seen(identifier, gated) for identifier, gated in seen]
    shuffled = data.draw(st.permutations(findings))

    first = compare(findings, known, "d" * 64)
    second = compare(shuffled, known, "d" * 64)

    assert baseline_json(known) == before
    assert {item.finding_id: item for item in first.entries} == {
        item.finding_id: item for item in second.entries
    }
    assert first.has_new_gated_findings == second.has_new_gated_findings
    assert first.has_new_gated_findings == any(
        gated and (identifier not in accepted or identifier in closed) for identifier, gated in seen
    )


@given(st.lists(IDS, min_size=1, max_size=6, unique=True), st.data())
def test_normal_run_never_closes_or_mutates_baseline(ids: list[str], data: st.DataObject) -> None:
    known = _baseline(ids, set())
    content = baseline_json(known).encode()
    observed = data.draw(st.lists(st.sampled_from(ids), unique=True))

    compare([Seen(item, True) for item in observed], known, "d" * 64)
    merged = merge_findings(known, [], "0.1.0")

    assert parse_baseline(content) == known
    assert not merged.changed
    assert all(item.status == "open" for item in merged.document.entries)


@given(TEXT, TEXT, TEXT, st.one_of(st.none(), TEXT))
def test_unrelated_target_or_mode_never_matches(
    target: str, other: str, mold: str, tool: str | None
) -> None:
    accepted = finding_id(target, "tools", mold, tool)
    known = _baseline([accepted], set())
    candidates = [finding_id(target, "agent", mold, tool)]
    if other != target:
        candidates.append(finding_id(other, "tools", mold, tool))

    result = compare([Seen(item, True) for item in candidates], known, "d" * 64)

    assert all(item.status == "new" for item in result.observed)
    assert [item.finding_id for item in result.unobserved] == [accepted]
