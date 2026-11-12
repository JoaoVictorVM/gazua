"""Masking policy of what reports publish: secrets and personal data out, declared test data in.

Detection is deterministic and based on formats and field names. It never reads or lists the
environment to find secrets, so a random value with no recognizable shape is not discovered.
Declared fixtures and canaries stay visible, but only as whole values: a detector match that
merely contains one is masked in full. When treating a field fails, the whole field is hidden
and a diagnostic names the field, never the value.
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field
from typing import Final, cast

from pydantic import JsonValue

from gazua.config.models import GazuaConfig
from gazua.diagnostics import SECRET_PATTERNS
from gazua.reports.builder import MAX_JSON_DEPTH, NotJsonError, plain_json
from gazua.reports.models import RedactionMode, ReportDiagnostic
from gazua.runtime.evidence import TRUNCATION_MARK
from gazua.runtime.processes import Capture

FIELD_FAILED: Final = "[redacted-field]"
PLACEHOLDERS: Final = {
    "private_key": "[redacted-private-key]",
    "secret": "[redacted-secret]",
    "email": "[redacted-email]",
    "card": "[redacted-card]",
    "cnpj": "[redacted-cnpj]",
    "cpf": "[redacted-cpf]",
    "phone": "[redacted-phone]",
    "sensitive": "[redacted-sensitive]",
    "personal": "[redacted-personal]",
}
SENSITIVE_FIELDS: Final = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "authorization",
        "api_key",
        "apikey",
        "cookie",
        "set_cookie",
        "private_key",
    }
)
PERSONAL_FIELDS: Final = frozenset(
    {
        "full_name",
        "fullname",
        "nome_completo",
        "address",
        "endereco",
        "street_address",
        "home_address",
        "birth_date",
        "birthdate",
        "date_of_birth",
        "dob",
        "data_nascimento",
        "data_de_nascimento",
    }
)
CI_VARIABLES: Final = (
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "TF_BUILD",
    "JENKINS_URL",
    "BUILD_BUILDID",
    "CIRCLECI",
)

_PRIVATE_KEY = re.compile(
    r"-----BEGIN[ A-Z0-9]*PRIVATE KEY-----.*?(?:-----END[ A-Z0-9]*PRIVATE KEY-----|\Z)", re.S
)
_KEY_VALUE = re.compile(
    r"(?i)\b(authorization|set-cookie|cookie|password|passwd|secret|token|api[_-]?key)"
    r"(\s*[:=]\s*)"
    r"(\"[^\"\n]*\"|'[^'\n]*'|(?:bearer|basic)\s+[^\s,;]+|[^\s,;]+)"
)
# Bounded local and domain parts keep matching linear on long text without an @.
_EMAIL = re.compile(r"[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,8}")
_CARD = re.compile(r"(?<![\d])\d(?:[ -]?\d){12,18}(?![\d])")
_CNPJ = re.compile(r"(?<![\d])\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}(?![\d])")
_CPF = re.compile(r"(?<![\d])\d{3}\.?\d{3}\.?\d{3}-?\d{2}(?![\d])")
_PHONE_BR = re.compile(r"(?<![\d+])\(?\d{2}\)?[ .-]?9?\d{4}[ .-]?\d{4}(?![\d])")
_PHONE_INTL = re.compile(r"\+\d{1,3}(?:[ .-]?\(?\d{1,4}\)?){2,5}(?![\d])")


def _luhn(digits: str) -> bool:
    total = 0
    for position, char in enumerate(reversed(digits)):
        value = int(char)
        if position % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _is_card(text: str) -> bool:
    digits = re.sub(r"[ -]", "", text)
    return 13 <= len(digits) <= 19 and _luhn(digits)


def _is_intl_phone(text: str) -> bool:
    return 8 <= sum(char.isdigit() for char in text) <= 15


def normalized_field(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def _matches(name: str, names: frozenset[str]) -> bool:
    if name in names:
        return True
    return any(name.endswith("_" + item) or name.startswith(item + "_") for item in names)


def field_category(name: str) -> str | None:
    """``sensitive`` or ``personal`` when a field name means its value is hidden in full."""
    normalized = normalized_field(name)
    if _matches(normalized, SENSITIVE_FIELDS):
        return "sensitive"
    if _matches(normalized, PERSONAL_FIELDS):
        return "personal"
    return None


def running_in_ci(environ: object) -> bool:
    """Whether a known CI indicator is set. Only these names are read; nothing is listed."""
    getter = getattr(environ, "get", None)
    if getter is None:
        return False
    for name in CI_VARIABLES:
        value = getter(name)
        if isinstance(value, str) and value.strip().lower() not in ("", "0", "false"):
            return True
    return False


@dataclass(frozen=True, slots=True)
class ReportRedactionPolicy:
    """What a report masks. Built only from validated declarations and the local option."""

    enabled: bool = True
    synthetic: frozenset[str] = frozenset()

    @classmethod
    def from_config(
        cls, config: GazuaConfig | None, *, no_redact: bool = False
    ) -> ReportRedactionPolicy:
        values: set[str] = set()
        if config is not None:
            values.update(config.canaries)
            for identity in (config.fixtures.attacker, config.fixtures.victim):
                if identity is None:
                    continue
                values.add(identity.id)
                values.update(str(item.id) for item in identity.records)
        return cls(enabled=not no_redact, synthetic=frozenset(item for item in values if item))

    @property
    def mode(self) -> RedactionMode:
        return "masked" if self.enabled else "none"


@dataclass(slots=True)
class ReportRedactor:
    """Applies a policy to text and JSON data and records each field that had to be hidden."""

    policy: ReportRedactionPolicy = field(default_factory=ReportRedactionPolicy)
    _found: list[ReportDiagnostic] = field(default_factory=list[ReportDiagnostic])
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def mode(self) -> RedactionMode:
        return self.policy.mode

    def diagnostics(self) -> list[ReportDiagnostic]:
        with self._lock:
            return list(self._found)

    def _failed(self, field: str, code: str = "redaction_failed") -> None:
        diagnostic = ReportDiagnostic(code=code, field=field, level="error")
        with self._lock:
            if diagnostic not in self._found:
                self._found.append(diagnostic)

    def _keep(self, match: str) -> bool:
        return match in self.policy.synthetic

    def _substitute(self, pattern: re.Pattern[str], category: str, value: str) -> str:
        placeholder = PLACEHOLDERS[category]

        def replace(match: re.Match[str]) -> str:
            text = match.group(0)
            return text if self._keep(text) else placeholder

        return pattern.sub(replace, value)

    def mask(self, value: str) -> str:
        """The text with every supported secret and personal value replaced."""
        if not self.policy.enabled:
            return value
        if self._keep(value):
            return value
        value = _PRIVATE_KEY.sub(PLACEHOLDERS["private_key"], value)
        value = self._substitute(SECRET_PATTERNS, "secret", value)

        def key_value(match: re.Match[str]) -> str:
            shown = match.group(3).strip("\"'")
            if self._keep(shown):
                return match.group(0)
            category = "sensitive"
            return match.group(1) + match.group(2) + PLACEHOLDERS[category]

        value = _KEY_VALUE.sub(key_value, value)
        value = self._substitute(_EMAIL, "email", value)

        def card(match: re.Match[str]) -> str:
            text = match.group(0)
            if self._keep(text) or not _is_card(text):
                return text
            return PLACEHOLDERS["card"]

        value = _CARD.sub(card, value)
        value = self._substitute(_CNPJ, "cnpj", value)
        value = self._substitute(_CPF, "cpf", value)
        value = self._substitute(_PHONE_BR, "phone", value)

        def phone(match: re.Match[str]) -> str:
            text = match.group(0)
            if self._keep(text) or not _is_intl_phone(text):
                return text
            return PLACEHOLDERS["phone"]

        return _PHONE_INTL.sub(phone, value)

    def text(self, value: str, field: str) -> str:
        try:
            if type(value) is not str:
                raise NotJsonError("type")
            return self.mask(value)
        # Treatment walks data that came from the target; any failure hides the whole field.
        except Exception:  # noqa: BLE001
            self._failed(field)
            return FIELD_FAILED

    def data(self, value: object, field: str) -> JsonValue:
        try:
            return self._walk(value, field, 0)
        # Treatment walks data that came from the target; any failure hides the whole field.
        except Exception:  # noqa: BLE001
            self._failed(field)
            return FIELD_FAILED

    def _number(self, value: int) -> JsonValue:
        if not self.policy.enabled or self._keep(str(value)):
            return value
        masked = self.mask(str(value))
        return value if masked == str(value) else masked

    def _walk(self, value: object, field: str, depth: int) -> JsonValue:
        if depth > MAX_JSON_DEPTH:
            raise NotJsonError("depth")
        kind = type(value)
        if value is None or kind in (bool, float):
            return plain_json(value)
        if kind is int:
            return self._number(cast("int", value))
        if kind is str:
            return self.mask(cast("str", value))
        if kind is list:
            return [self._walk(item, field, depth + 1) for item in cast("list[object]", value)]
        if kind is dict:
            return self._object(cast("dict[object, object]", value), field, depth)
        raise NotJsonError("type")

    def _object(self, value: dict[object, object], field: str, depth: int) -> JsonValue:
        found: dict[str, JsonValue] = {}
        for key, item in value.items():
            try:
                if type(key) is not str:
                    raise NotJsonError("key")
                shown_key = self.mask(key)
            # A key that cannot be treated hides its whole entry.
            except Exception:  # noqa: BLE001
                self._failed(field)
                continue
            category = field_category(key) if self.policy.enabled else None
            if category is not None and not (type(item) is str and self._keep(item)):
                treated: JsonValue = PLACEHOLDERS[category]
            else:
                try:
                    treated = self._walk(item, field, depth + 1)
                # One failing value hides that value only.
                except Exception:  # noqa: BLE001
                    self._failed(field)
                    treated = FIELD_FAILED
            unique = shown_key
            number = 2
            while unique in found:
                unique = f"{shown_key}#{number}"
                number += 1
            if unique != shown_key:
                self._failed(field, "redacted_key_collision")
            found[unique] = treated
        return found


class EngineRedaction:
    """The engine's evidence redactor interface, backed by a report policy.

    The engine keeps its conservative redactor by default; tools runs that produce reports pass
    this one so persisted evidence follows the same policy as the report.
    """

    def __init__(self, redactor: ReportRedactor) -> None:
        self.redactor = redactor

    def text(self, value: str) -> str:
        return self.redactor.text(value, "engine.evidence")

    def data(self, value: object) -> JsonValue:
        return self.redactor.data(value, "engine.evidence")

    def capture(self, capture: Capture) -> str:
        text = self.text(capture.data.decode("utf-8", errors="replace"))
        return text + TRUNCATION_MARK if capture.truncated else text


def utf8_size(value: JsonValue) -> int:
    return len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8"))
