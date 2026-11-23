"""The local receipt binds one confirmation to one origin and one configuration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from gazua.config.models import GazuaConfig
from gazua.http.authorization import (
    ReceiptError,
    check_receipt,
    config_hash,
    new_receipt,
    receipt_path,
    write_receipt,
)
from gazua.http.models import AuthorizationReceipt, render_receipt_json_schema

ROOT = Path(__file__).resolve().parents[2]


def _config(**changes: Any) -> GazuaConfig:
    http: dict[str, Any] = {
        "endpoint": "https://agent.test.example/api",
        "headers": {"X-Test-Tenant": "gazua-fixture"},
        "real_side_effects": "i_understand",
    }
    http.update(changes.pop("http", {}))
    document: dict[str, Any] = {
        "schema_version": 1,
        "http": http,
        "allowed_targets": ["agent.test.example"],
        **changes,
    }
    return GazuaConfig.model_validate(document)


def test_receipt_binds_origin_and_config_hash(tmp_path: Path) -> None:
    config = _config()
    path = write_receipt(tmp_path, new_receipt(config))

    assert path == receipt_path(tmp_path)
    receipt = check_receipt(tmp_path, config)
    assert receipt.origin == "https://agent.test.example"
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert set(stored) == {"schema_version", "origin", "config_hash", "confirmed_at", "authorized"}
    assert "gazua-fixture" not in path.read_text(encoding="utf-8")
    for changed in (
        _config(http={"endpoint": "https://agent.test.example/other"}),
        _config(http={"headers": {"X-Test-Tenant": "other"}}),
        _config(allowed_targets=["agent.test.example", "localhost"]),
        _config(http={"real_side_effects": None}),
    ):
        assert config_hash(changed) != config_hash(config)
        with pytest.raises(ReceiptError) as caught:
            check_receipt(tmp_path, changed)
        assert caught.value.code == "http_authorization_changed"
    # Unrelated settings keep the confirmation.
    check_receipt(tmp_path, _config(limits={"timeout": 5}, canaries=["GAZUA-CANARY-x"]))


def test_missing_corrupt_or_unknown_receipts_block(tmp_path: Path) -> None:
    config = _config()
    with pytest.raises(ReceiptError) as missing:
        check_receipt(tmp_path, config)
    assert missing.value.code == "http_authorization_missing"

    path = write_receipt(tmp_path, new_receipt(config))
    for content in ("{", "[]", json.dumps({**json.loads(path.read_text()), "schema_version": 2})):
        path.write_text(content, encoding="utf-8")
        with pytest.raises(ReceiptError) as caught:
            check_receipt(tmp_path, config)
        assert caught.value.code == "http_authorization_invalid"
    data = json.loads(new_receipt(config).model_dump_json())
    data["authorized"] = False
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ReceiptError):
        check_receipt(tmp_path, config)


def test_receipt_schema_matches_generator() -> None:
    published = ROOT / "src/gazua/schemas/http-authorization-v1.schema.json"
    assert published.read_text(encoding="utf-8").replace("\r\n", "\n") == (
        render_receipt_json_schema()
    )
    assert AuthorizationReceipt.model_json_schema()["properties"]["authorized"]["const"] is True


@settings(max_examples=50)
@given(
    headers=st.dictionaries(
        st.from_regex(r"X-[A-Za-z]{1,8}", fullmatch=True),
        st.from_regex(r"[a-z0-9-]{0,12}", fullmatch=True),
        max_size=4,
    ),
    hosts=st.lists(st.sampled_from(["agent.test.example", "LOCALHOST", "127.0.0.1"]), max_size=3),
)
def test_hash_ignores_order_and_case_but_not_content(
    headers: dict[str, str], hosts: list[str]
) -> None:
    lowered = {name.lower() for name in headers}
    if len(lowered) != len(headers) or len(set(hosts)) != len(hosts):
        return
    base = _config(http={"headers": headers}, allowed_targets=["agent.test.example", *hosts])
    reordered = _config(
        http={"headers": dict(reversed(list(headers.items())))},
        allowed_targets=list(reversed(["agent.test.example", *hosts])),
    )
    assert config_hash(base) == config_hash(reordered)
    changed = _config(
        http={"headers": {**headers, "X-Extra-Header": "1"}},
        allowed_targets=["agent.test.example", *hosts],
    )
    assert config_hash(base) != config_hash(changed)
