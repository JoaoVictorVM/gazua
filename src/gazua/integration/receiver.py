"""Explicit transport from a test tool to the run's local receiver.

The URL is a logical destination under ``.gazua.test`` and is never opened on the network. The
physical connection is plain HTTP to ``127.0.0.1`` on the port that the validated session
names, with the execution's token, so there is no DNS lookup, no HTTPS downgrade and no
certificate to ignore. Unlike ``gazua.wrap``, this helper never sends anything outside a
supervised execution.
"""

from __future__ import annotations

import base64
import http.client
import json
from collections.abc import Mapping
from typing import cast

from gazua.integration.destinations import exfiltration_url_problem
from gazua.integration.session import InvalidSession, session_state

ALLOWED_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
MAX_BODY_BYTES = 1024 * 1024
COLLECT_PATH = "/collect"
TOKEN_HEADER = "X-Gazua-Token"  # noqa: S105
ENVELOPE_VERSION = 1
_TIMEOUT_SECONDS = 5.0


class GazuaReceiverError(Exception):
    """The request did not reach the local receiver. ``reason`` is a short stable code."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"Gazua did not deliver this request to the local receiver ({reason}).")


def _content_type(headers: Mapping[str, str] | None) -> str | None:
    if headers is None:
        return None
    # Callers in the tested process are untyped, so names and values are checked here.
    for name, value in cast("Mapping[object, object]", headers).items():
        if (
            isinstance(name, str)
            and name.lower() == "content-type"
            and isinstance(value, str)
            and value.isprintable()
        ):
            return value[:200]
    return None


def _body(body: object) -> bytes:
    if isinstance(body, str):
        return body.encode("utf-8")
    if isinstance(body, bytes | bytearray):
        return bytes(body)
    raise TypeError("body must be bytes or str.")


def send_to_receiver(
    url: str,
    *,
    method: str = "POST",
    body: bytes | str = b"",
    headers: Mapping[str, str] | None = None,
) -> None:
    """Delivers an exfiltration attempt to the local receiver of the current execution.

    Only ``Content-Type`` is kept from ``headers``; credentials, cookies and proxy headers are
    never forwarded. Raises ``GazuaReceiverError`` before any lookup or connection when the
    URL is not reserved or there is no receiver in this execution.
    """
    if not isinstance(cast("object", url), str) or exfiltration_url_problem(url) is not None:
        raise GazuaReceiverError("invalid_exfiltration_domain")
    if method not in ALLOWED_METHODS:
        raise GazuaReceiverError("invalid_method")
    data = _body(body)
    if len(data) > MAX_BODY_BYTES:
        raise GazuaReceiverError("body_too_large")
    state = session_state()
    if state is None:
        raise GazuaReceiverError("no_session")
    if isinstance(state, InvalidSession):
        raise GazuaReceiverError("invalid_session")
    if state.execution is None or state.execution.receiver is None:
        raise GazuaReceiverError("receiver_unavailable")
    endpoint = state.execution.receiver
    envelope: dict[str, object] = {
        "schema_version": ENVELOPE_VERSION,
        "execution_id": endpoint.execution_id,
        "method": method,
        "logical_url": url,
        "content_type": _content_type(headers),
    }
    try:
        envelope["body_utf8"] = data.decode("utf-8")
    except UnicodeDecodeError:
        envelope["body_base64"] = base64.b64encode(data).decode("ascii")
    payload = json.dumps(envelope, ensure_ascii=True).encode("ascii")
    # http.client never reads proxy variables, so the connection stays on loopback.
    connection = http.client.HTTPConnection(endpoint.host, endpoint.port, timeout=_TIMEOUT_SECONDS)
    try:
        connection.request(
            "POST",
            COLLECT_PATH,
            body=payload,
            headers={"Content-Type": "application/json", TOKEN_HEADER: endpoint.token},
        )
        response = connection.getresponse()
        response.read(4096)
        status = response.status
    except (OSError, http.client.HTTPException):
        raise GazuaReceiverError("receiver_unreachable") from None
    finally:
        connection.close()
    if status != 202:
        raise GazuaReceiverError("receiver_rejected")
