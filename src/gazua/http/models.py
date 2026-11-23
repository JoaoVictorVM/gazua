"""Contracts of the HTTP adapter: the parsed endpoint, header rules, limits and the receipt.

Parsing never resolves a name or opens a connection. The endpoint keeps exactly what the
configuration declared; nothing a mold, a response or the environment says can change it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Annotated, Any, Final, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

MAX_REQUEST_BYTES: Final = 1024 * 1024
MAX_RESPONSE_BYTES: Final = 1024 * 1024
MAX_ENDPOINT_CHARACTERS: Final = 2048
MAX_HEADERS: Final = 32
MAX_HEADER_VALUE_CHARACTERS: Final = 1024
LOOPBACK_HOSTS: Final = frozenset({"localhost", "127.0.0.1", "::1"})
DEFAULT_PORTS: Final = {"http": 80, "https": 443}
REAL_SIDE_EFFECTS: Final = "i_understand"
RECEIPT_SCHEMA_FILE: Final = "http-authorization-v1.schema.json"

# Gazua sets these itself, and credentials are out of scope: a static header can never
# replace the identification, the trace channel or an authentication secret.
RESERVED_HEADERS: Final = frozenset(
    {
        "accept",
        "authorization",
        "connection",
        "content-length",
        "content-type",
        "cookie",
        "expect",
        "host",
        "keep-alive",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "user-agent",
        "x-gazua-otlp-endpoint",
        "x-gazua-run",
        "x-gazua-trace-token",
    }
)
HEADER_NAME_PATTERN: Final = r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$"
_HEADER_NAME = re.compile(HEADER_NAME_PATTERN)
_SCHEMA_BASE: Final = "https://raw.githubusercontent.com/JoaoVictorVM/gazua/main/src/gazua/schemas/"


class EndpointError(ValueError):
    """The endpoint is not an absolute, unambiguous URL Gazua accepts. ``code`` is public."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class Endpoint:
    """One parsed endpoint. ``host`` is lowercase, without brackets for IPv6."""

    scheme: Literal["http", "https"]
    host: str
    port: int
    path: str
    query: str

    @property
    def loopback(self) -> bool:
        return self.host in LOOPBACK_HOSTS

    @property
    def origin(self) -> str:
        """``scheme://host[:port]``, the port left out when it is the scheme's default."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        port = "" if DEFAULT_PORTS[self.scheme] == self.port else f":{self.port}"
        return f"{self.scheme}://{host}{port}"

    @property
    def target(self) -> str:
        """The request target sent on the wire: the declared path and fixed query."""
        return self.path + (f"?{self.query}" if self.query else "")


def parse_endpoint(value: str) -> Endpoint:
    """The endpoint of ``value``, or ``EndpointError`` naming what is wrong.

    Userinfo, fragments, wildcards, empty hosts, non-ASCII hosts and whitespace are refused,
    so two readers cannot disagree about where a request goes.
    """
    if len(value) > MAX_ENDPOINT_CHARACTERS:
        raise EndpointError("http_endpoint_invalid", "The endpoint is longer than 2048 characters.")
    if not value.isascii() or any(not char.isprintable() or char.isspace() for char in value):
        raise EndpointError(
            "http_endpoint_invalid",
            "The endpoint must be ASCII without spaces or control characters; "
            "write an international host in its xn-- form.",
        )
    try:
        parts = urlsplit(value)
        port = parts.port
        hostname = parts.hostname
    except ValueError:
        raise EndpointError("http_endpoint_invalid", "The endpoint is not a valid URL.") from None
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise EndpointError(
            "http_endpoint_invalid", "The endpoint must start with http:// or https://."
        )
    if "@" in parts.netloc:
        raise EndpointError("http_endpoint_invalid", "The endpoint cannot carry user information.")
    if parts.fragment or "#" in value:
        raise EndpointError("http_endpoint_invalid", "The endpoint cannot have a fragment.")
    if not hostname:
        raise EndpointError("http_endpoint_invalid", "The endpoint needs a host.")
    if "*" in hostname or "%" in hostname:
        raise EndpointError("http_endpoint_invalid", "The endpoint host must be exact.")
    if port == 0:
        raise EndpointError(
            "http_endpoint_invalid", "The endpoint port must be between 1 and 65535."
        )
    path = parts.path or "/"
    if not path.startswith("/"):
        raise EndpointError("http_endpoint_invalid", "The endpoint path must be absolute.")
    return Endpoint(
        scheme="https" if scheme == "https" else "http",
        host=hostname.lower().rstrip("."),
        port=port if port is not None else DEFAULT_PORTS[scheme],
        path=path,
        query=parts.query,
    )


def header_problem(name: str, value: str) -> str | None:
    """Why a static header is refused; None when it can be sent as it is."""
    if not _HEADER_NAME.fullmatch(name):
        return "Header names use only token characters."
    if name.lower() in RESERVED_HEADERS:
        return "This header is set by Gazua or carries credentials; it cannot be declared."
    if len(value) > MAX_HEADER_VALUE_CHARACTERS:
        return "Header values are at most 1024 characters."
    if any(char in value for char in "\r\n\x00") or not value.isprintable():
        return "Header values cannot contain line breaks or control characters."
    return None


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
UtcTimestamp = Annotated[str, Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$")]


class AuthorizationReceipt(_Strict):
    """The local record that an operator confirmed real effects against one origin and config.

    It holds no typed phrase, header, token, response or personal identity. It proves that the
    local gate was passed for this configuration, never a legal authorization.
    """

    model_config = ConfigDict(title="Gazua HTTP authorization receipt")

    schema_version: Literal[1]
    origin: Annotated[str, Field(min_length=1, max_length=MAX_ENDPOINT_CHARACTERS)]
    config_hash: Sha256
    confirmed_at: UtcTimestamp
    authorized: Literal[True]


def build_receipt_json_schema() -> dict[str, Any]:
    from gazua.config.models import SCHEMA_DIALECT

    schema = AuthorizationReceipt.model_json_schema(mode="validation")
    return {"$schema": SCHEMA_DIALECT, "$id": _SCHEMA_BASE + RECEIPT_SCHEMA_FILE, **schema}


def render_receipt_json_schema() -> str:
    return json.dumps(build_receipt_json_schema(), indent=2) + "\n"


__all__ = [
    "LOOPBACK_HOSTS",
    "MAX_HEADERS",
    "MAX_REQUEST_BYTES",
    "MAX_RESPONSE_BYTES",
    "REAL_SIDE_EFFECTS",
    "RECEIPT_SCHEMA_FILE",
    "RESERVED_HEADERS",
    "AuthorizationReceipt",
    "Endpoint",
    "EndpointError",
    "header_problem",
    "parse_endpoint",
    "render_receipt_json_schema",
]
