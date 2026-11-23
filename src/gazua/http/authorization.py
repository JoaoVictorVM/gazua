"""The local authorization receipt: canonical hash of the HTTP block and its storage.

The receipt binds one confirmation to one origin and one configuration. Changing the endpoint,
a header, the allowlist or the real effects literal changes the hash and blocks the next run
until the operator confirms again. The receipt is read only from ``.gazua/`` under the project
root, never from a path a target or a flag can choose.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from pydantic import ValidationError

from gazua.config.models import GazuaConfig
from gazua.http import RECEIPT_FILE
from gazua.http.models import AuthorizationReceipt, parse_endpoint

MAX_RECEIPT_BYTES: Final = 64 * 1024


class ReceiptError(Exception):
    """The receipt is missing, unreadable or does not match. ``code`` is public."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def receipt_path(project_root: Path) -> Path:
    return project_root / ".gazua" / RECEIPT_FILE


def canonical_block(config: GazuaConfig) -> dict[str, object]:
    """The part of the configuration a confirmation covers, in one canonical form."""
    http = config.http
    if http is None:
        raise ValueError("The configuration declares no HTTP target.")
    endpoint = parse_endpoint(http.endpoint)
    return {
        "origin": endpoint.origin,
        "target": endpoint.target,
        "headers": sorted([name.lower(), value] for name, value in http.headers.items()),
        "allowed_targets": sorted({host.lower() for host in config.allowed_targets}),
        "real_side_effects": http.real_side_effects,
    }


def config_hash(config: GazuaConfig) -> str:
    canonical = json.dumps(
        canonical_block(config), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def new_receipt(config: GazuaConfig, *, now: datetime | None = None) -> AuthorizationReceipt:
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    http = config.http
    if http is None:
        raise ValueError("The configuration declares no HTTP target.")
    return AuthorizationReceipt(
        schema_version=1,
        origin=parse_endpoint(http.endpoint).origin,
        config_hash=config_hash(config),
        confirmed_at=moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
        authorized=True,
    )


def write_receipt(project_root: Path, receipt: AuthorizationReceipt) -> Path:
    """Writes the receipt atomically under ``.gazua/``, readable only by the user when possible."""
    from gazua.runtime.evidence import safe_directory, write_atomic

    folder = safe_directory(project_root, ".gazua")
    path = folder / RECEIPT_FILE
    if path.is_symlink():
        raise OSError("The receipt path is a link.")
    write_atomic(path, receipt.model_dump_json(indent=2) + "\n")
    # Windows has no POSIX modes; the file then keeps the folder's permissions.
    if os.name != "nt":
        path.chmod(0o600)
    return path


def read_receipt(project_root: Path) -> AuthorizationReceipt:
    path = receipt_path(project_root)
    if path.is_symlink() or not path.is_file():
        raise ReceiptError("http_authorization_missing")
    try:
        content = path.read_bytes()
    except OSError:
        raise ReceiptError("http_authorization_missing") from None
    if len(content) > MAX_RECEIPT_BYTES:
        raise ReceiptError("http_authorization_invalid")
    try:
        return AuthorizationReceipt.model_validate_json(content)
    except ValidationError:
        raise ReceiptError("http_authorization_invalid") from None


def check_receipt(project_root: Path, config: GazuaConfig) -> AuthorizationReceipt:
    """The receipt that matches this configuration, or ``ReceiptError`` saying why not."""
    receipt = read_receipt(project_root)
    http = config.http
    if http is None:
        raise ReceiptError("http_authorization_missing")
    if receipt.origin != parse_endpoint(http.endpoint).origin or receipt.config_hash != config_hash(
        config
    ):
        raise ReceiptError("http_authorization_changed")
    return receipt


__all__ = [
    "ReceiptError",
    "canonical_block",
    "check_receipt",
    "config_hash",
    "new_receipt",
    "read_receipt",
    "receipt_path",
    "write_receipt",
]
