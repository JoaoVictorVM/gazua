import ast
import inspect
import json
from pathlib import Path
from typing import Any, ClassVar

import pytest
from hypothesis import given
from hypothesis import strategies as st

import gazua.reports.redaction as redaction_module
from gazua.reports import capture as capture_module
from gazua.reports.capture import limited
from gazua.reports.redaction import (
    FIELD_FAILED,
    PLACEHOLDERS,
    ReportRedactionPolicy,
    ReportRedactor,
    field_category,
    running_in_ci,
)

CANARY = "GAZUA-CANARY-7f3a9c"
SECRET = "sk-" + "A1b2C3d4E5f6G7h8I9j0K1l2"
CARD = "4111 1111 1111 1111"
PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsecretbody\n-----END RSA PRIVATE KEY-----"
)


def redactor(*synthetic: str, enabled: bool = True) -> ReportRedactor:
    return ReportRedactor(ReportRedactionPolicy(enabled=enabled, synthetic=frozenset(synthetic)))


@pytest.mark.parametrize(
    ("value", "placeholder"),
    [
        (SECRET, "secret"),
        ("ghp_" + "a" * 36, "secret"),
        ("AKIA" + "ABCDEFGHIJKLMNOP", "secret"),
        ("mail me at maria.silva@example.com now", "email"),
        ("call (11) 98765-4321", "phone"),
        ("call +55 11 98765 4321", "phone"),
        ("cpf 123.456.789-09", "cpf"),
        ("cpf 12345678909", "cpf"),
        ("cnpj 12.345.678/0001-95", "cnpj"),
        (f"card {CARD}", "card"),
        ("card 4111111111111111", "card"),
    ],
)
def test_masks_supported_secrets_and_personal_data(value: str, placeholder: str) -> None:
    treated = redactor().text(value, "field")

    assert PLACEHOLDERS[placeholder] in treated
    digits = [part for part in value.split() if any(char.isdigit() for char in part)]
    assert all(part not in treated for part in digits if len(part) > 4)


def test_card_needs_valid_luhn() -> None:
    assert redactor().text("order 4111111111111112", "field").startswith("order ")
    assert PLACEHOLDERS["card"] not in redactor().text("ref 4111111111111112", "field")


def test_masks_sensitive_fields_and_private_key_body() -> None:
    treated = redactor().data(
        {
            "Password": "hunter2",
            "api-key": "plain",
            "Set-Cookie": "session=abc",
            "full_name": "Maria Silva",
            "address": {"street": "Rua A, 1"},
            "birth_date": "1990-01-01",
            "note": f"key {PRIVATE_KEY} end",
            "headers": "Authorization: Bearer abc.def.ghi",
        },
        "field",
    )
    text = json.dumps(treated)

    for raw in (
        "hunter2",
        "plain",
        "session=abc",
        "Maria",
        "Rua A",
        "1990",
        "secretbody",
        "abc.def",
    ):
        assert raw not in text
    assert isinstance(treated, dict)
    assert treated["Password"] == PLACEHOLDERS["sensitive"]
    assert treated["full_name"] == PLACEHOLDERS["personal"]
    assert treated["address"] == PLACEHOLDERS["personal"]
    assert PLACEHOLDERS["private_key"] in str(treated["note"])
    assert field_category("client_secret") == "sensitive"
    assert field_category("order_id") is None


def test_declared_synthetic_values_remain_visible() -> None:
    chosen = redactor(CANARY, "victim@example.test", "12345678909")
    treated = chosen.data(
        {
            "note": f"canary {CANARY} for victim@example.test",
            "owner": "victim@example.test",
            "id": 12345678909,
            "token": CANARY,
            "other": "intruder@example.test",
        },
        "field",
    )

    assert isinstance(treated, dict)
    assert treated["note"] == f"canary {CANARY} for victim@example.test"
    assert treated["owner"] == "victim@example.test"
    assert treated["id"] == 12345678909
    assert treated["token"] == CANARY
    assert treated["other"] == PLACEHOLDERS["email"]


def test_synthetic_substring_cannot_exempt_larger_secret() -> None:
    larger = "sk-" + CANARY.replace("-", "") + "XXXXXXXXXXXX"
    chosen = redactor(CANARY, "victim@example.test")

    assert larger not in chosen.text(f"value {larger}", "field")
    assert "xvictim@example.test" not in chosen.text("xvictim@example.test", "field")


class Hostile:
    def __repr__(self) -> str:
        raise AssertionError("repr must never run")

    def __str__(self) -> str:
        raise AssertionError("str must never run")


def test_failed_field_and_key_never_fall_back_to_raw() -> None:
    chosen = redactor()
    treated = chosen.data(
        {"ok": "value", "bad": Hostile(), 3: "hidden by key", "nested": [Hostile()]}, "evidence"
    )

    assert isinstance(treated, dict)
    assert treated["ok"] == "value"
    assert treated["bad"] == FIELD_FAILED
    assert treated["nested"] == FIELD_FAILED
    assert "hidden by key" not in json.dumps(treated)
    assert chosen.data(Hostile(), "evidence") == FIELD_FAILED
    assert chosen.text(Hostile(), "evidence") == FIELD_FAILED  # type: ignore[arg-type]
    codes = {(item.code, item.field, item.level) for item in chosen.diagnostics()}
    assert codes == {("redaction_failed", "evidence", "error")}
    deep: Any = "leaf"
    for _ in range(80):
        deep = [deep]
    assert chosen.data(deep, "deep") == FIELD_FAILED


def test_redacted_key_collision_does_not_drop_entries() -> None:
    chosen = redactor()
    treated = chosen.data({"a@example.com": 1, "b@example.com": 2, "c@example.com": 3}, "f")

    assert isinstance(treated, dict)
    assert sorted(treated.values()) == [1, 2, 3]  # type: ignore[type-var]
    assert all("example.com" not in key for key in treated)
    assert {item.code for item in chosen.diagnostics()} == {"redacted_key_collision"}


def test_mask_before_truncate() -> None:
    chosen = redactor()
    filler = "x" * (16 * 1024 - 10)
    treated = chosen.data(f"{filler} {SECRET}", "field")
    content, truncated = limited(treated)

    assert truncated is True
    assert isinstance(content, str)
    assert SECRET[:8] not in content
    assert len(content.encode("utf-8")) <= 16 * 1024


def test_no_environment_enumeration_or_provider_key_read(monkeypatch: pytest.MonkeyPatch) -> None:
    for module in (redaction_module, capture_module):
        tree = ast.parse(Path(inspect.getfile(module)).read_text(encoding="utf-8"))
        names = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        assert "environ" not in names
        assert "getenv" not in names

    class Recording(dict[str, str]):
        asked: ClassVar[list[str]] = []

        def get(self, key: str, default: Any = None) -> Any:  # type: ignore[override]
            self.asked.append(key)
            return super().get(key, default)

        def __iter__(self) -> Any:
            raise AssertionError("the environment is never listed")

    environment = Recording({"OPENAI_API_KEY": SECRET, "GITLAB_CI": "true"})
    assert running_in_ci(environment) is True
    assert set(Recording.asked) <= set(redaction_module.CI_VARIABLES)
    assert running_in_ci(Recording({"CI": "false", "TF_BUILD": "0", "CIRCLECI": ""})) is False


@given(st.text(max_size=200))
def test_masked_text_never_keeps_a_detected_secret(prefix: str) -> None:
    treated = redactor().text(f"{prefix} {SECRET} ", "field")

    assert SECRET not in treated
