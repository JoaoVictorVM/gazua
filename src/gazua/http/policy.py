"""The destination gate of an HTTP run, checked before any socket opens.

The host must match ``allowed_targets`` exactly, HTTPS is required off the loopback, the real
effects literal must be declared and the local receipt must match the configuration. Nothing
here reads the environment, so no variable can widen the allowlist or turn a check off.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from gazua.config.diagnostics import sanitize
from gazua.config.models import GazuaConfig
from gazua.diagnostics import ConfigError, Diagnostic
from gazua.http.models import REAL_SIDE_EFFECTS, Endpoint, EndpointError, parse_endpoint

AUTHORIZATION_HINT: Final = (
    "Confirm it with gazua init --http URL, using the endpoint in gazua.yaml; that keeps the "
    "file and writes a new receipt in .gazua/."
)
_RECEIPT_MESSAGES: Final = {
    "http_authorization_missing": "No authorization receipt for this HTTP target.",
    "http_authorization_invalid": "The authorization receipt cannot be read.",
    "http_authorization_changed": (
        "The HTTP target, its headers, the allowlist or real_side_effects changed since the "
        "authorization was confirmed."
    ),
}


def _failure(code: str, message: str, field: str | None = "http") -> ConfigError:
    return ConfigError([Diagnostic(code=code, field=field, message=message)])


def allowed(endpoint: Endpoint, allowed_targets: list[str]) -> bool:
    """Exact host equality, ignoring case only: no suffix, substring or reverse lookup."""
    return endpoint.host in {host.lower().rstrip(".") for host in allowed_targets}


def check_destination(config: GazuaConfig) -> Endpoint:
    """The endpoint when its host and transport are allowed; ``ConfigError`` otherwise."""
    http = config.http
    if http is None:
        raise _failure("http_target_missing", "The configuration declares no HTTP target.")
    try:
        endpoint = parse_endpoint(http.endpoint)
    except EndpointError as error:
        raise _failure(error.code, str(error), "http.endpoint") from None
    if not allowed(endpoint, config.allowed_targets):
        raise _failure(
            "http_target_not_allowed",
            f"Host {sanitize(endpoint.host)} is not in allowed_targets; no request was sent.",
            "allowed_targets",
        )
    if not endpoint.loopback and endpoint.scheme != "https":
        raise _failure(
            "http_tls_required",
            "HTTPS is required for a host outside the loopback; no request was sent.",
            "http.endpoint",
        )
    return endpoint


def check_run(config: GazuaConfig, project_root: Path) -> Endpoint:
    """Every gate a run passes before its first request, in a fixed order.

    The destination comes first, so a disallowed host is reported even without a receipt.
    """
    from gazua.http.authorization import ReceiptError, check_receipt

    endpoint = check_destination(config)
    http = config.http
    if http is None or http.real_side_effects != REAL_SIDE_EFFECTS:
        raise _failure(
            "http_real_side_effects_missing",
            "HTTP has no dry-run: every request can change the endpoint for real. Declare "
            "real_side_effects: i_understand under http once you accept that.",
            "http.real_side_effects",
        )
    try:
        check_receipt(project_root, config)
    except ReceiptError as error:
        message = _RECEIPT_MESSAGES.get(error.code, _RECEIPT_MESSAGES["http_authorization_missing"])
        raise _failure("http_authorization_missing", f"{message} {AUTHORIZATION_HINT}") from None
    if config.traces is not None:
        from gazua.otel import EXTRA_MISSING_CODE, EXTRA_MISSING_MESSAGE, extra_available

        if not extra_available():
            raise _failure(EXTRA_MISSING_CODE, EXTRA_MISSING_MESSAGE, "traces")
    return endpoint


__all__ = ["AUTHORIZATION_HINT", "allowed", "check_destination", "check_run"]
