import json
import os
from pathlib import Path

import pytest
from baseline_factory import (
    FINDING_A,
    FINDING_B,
    baseline,
    baseline_bytes,
    document_data,
    entry,
    reference,
)

from gazua.baseline.models import ScenarioReference
from gazua.baseline.storage import (
    MAX_BASELINE_BYTES,
    AcceptedFinding,
    BaselineError,
    merge_findings,
    parse_baseline,
    read_baseline,
    resolve_baseline_path,
    write_baseline,
)

SENTINEL = "GAZUA-SENTINEL-do-not-print"


def code_of(content: bytes) -> str:
    with pytest.raises(BaselineError) as caught:
        parse_baseline(content)
    assert SENTINEL not in str(caught.value)
    assert SENTINEL not in caught.value.message
    return caught.value.code


def test_limits_bytes_depth_and_entries() -> None:
    assert code_of(b" " * (MAX_BASELINE_BYTES + 1)) == "baseline_limit_exceeded"
    deep: object = SENTINEL
    for _ in range(20):
        deep = [deep]
    data = {**document_data(), "entries": deep}
    assert code_of(json.dumps(data).encode()) == "baseline_limit_exceeded"
    many = {**document_data(), "entries": [{}] * 10_001}
    assert code_of(json.dumps(many).encode()) == "baseline_limit_exceeded"
    references = [reference(f"{index:064x}") for index in range(100_001)]
    huge = {**document_data(), "entries": [{"scenarios": references}]}
    assert code_of(json.dumps(huge).encode()) == "baseline_limit_exceeded"


def test_rejects_duplicate_json_keys_and_nonfinite_numbers() -> None:
    duplicated = b'{"schema_version": 1, "schema_version": 1, "revision": 1}'
    assert code_of(duplicated) == "baseline_invalid"
    assert code_of(b'{"schema_version": 1, "revision": NaN}') == "baseline_invalid"
    assert code_of(b'{"schema_version": 1, "revision": Infinity}') == "baseline_invalid"
    assert code_of(b'{"schema_version": true}') == "baseline_invalid"
    assert code_of(f'{{"schema_version": 1, "{SENTINEL}": 1}}'.encode()) == "baseline_invalid"
    assert code_of(b"\xff\xfe") == "baseline_invalid"
    assert code_of(f"[{json.dumps(SENTINEL)}]".encode()) == "baseline_invalid"
    assert code_of(b'{"schema_version": 1, "revision": 1') == "baseline_invalid"


def test_rejects_symlinks_and_reserved_paths(tmp_path: Path) -> None:
    root = tmp_path / "project"
    (root / ".gazua").mkdir(parents=True)
    (root / "folder").mkdir()
    config = root / "gazua.yaml"
    config.write_text("schema_version: 1\n", encoding="utf-8")

    for path in (Path(".gazua/baseline.json"), Path("../outside.json"), Path("folder")):
        with pytest.raises(BaselineError) as caught:
            resolve_baseline_path(root, path, config_path=config)
        assert caught.value.code == "baseline_path_invalid"
    with pytest.raises(BaselineError):
        resolve_baseline_path(root, Path("gazua.yaml"), config_path=config)

    real = root / "real.json"
    real.write_bytes(baseline_bytes(entry()))
    link = root / "linked.json"
    try:
        os.symlink(real, link)
    except OSError:
        pytest.skip("this system does not allow symlinks for this user")
    with pytest.raises(BaselineError) as caught:
        resolve_baseline_path(root, Path("linked.json"), config_path=config)
    assert caught.value.code == "baseline_path_invalid"
    with pytest.raises(BaselineError):
        read_baseline(link)

    assert resolve_baseline_path(root, Path("gazua-baseline.json")) == root / "gazua-baseline.json"


def test_atomic_failure_preserves_original_bytes(tmp_path: Path) -> None:
    path = tmp_path / "gazua-baseline.json"
    original = baseline_bytes(entry())
    path.write_bytes(original)
    changed = baseline(entry(), entry(FINDING_B), revision=2)

    def fail() -> None:
        raise OSError("disk full")

    with pytest.raises(BaselineError) as caught:
        write_baseline(path, changed, original, before_replace=fail)

    assert caught.value.code == "baseline_write_failed"
    assert path.read_bytes() == original
    assert sorted(item.name for item in tmp_path.iterdir()) == ["gazua-baseline.json"]


def test_conflicting_revision_is_not_overwritten(tmp_path: Path) -> None:
    path = tmp_path / "gazua-baseline.json"
    read = baseline_bytes(entry())
    meanwhile = baseline_bytes(entry(), entry(FINDING_B), revision=2)
    path.write_bytes(meanwhile)

    with pytest.raises(BaselineError) as caught:
        write_baseline(path, baseline(entry(status="closed"), revision=2), read)

    assert caught.value.code == "baseline_conflict"
    assert path.read_bytes() == meanwhile
    assert sorted(item.name for item in tmp_path.iterdir()) == ["gazua-baseline.json"]

    with pytest.raises(BaselineError) as created:
        write_baseline(path, baseline(entry()), None)
    assert created.value.code == "baseline_conflict"


def test_noop_merge_preserves_bytes(tmp_path: Path) -> None:
    path = tmp_path / "gazua-baseline.json"
    existing = baseline(entry(), revision=3)
    content = write_baseline(path, existing, None)
    again = AcceptedFinding(FINDING_A, "tools", (ScenarioReference.model_validate(reference()),))

    merged = merge_findings(read_baseline(path).document, [again], "9.9.9")

    assert not merged.changed
    assert merged.document.revision == 3
    assert merged.document.gazua_version == "0.1.0.dev0"
    assert path.read_bytes() == content
    assert content.endswith(b"\n")
    assert read_baseline(path).document == existing
    assert FINDING_A in content.decode("utf-8")
