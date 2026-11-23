"""One bounded request to the authorized endpoint and its normalized response.

The client speaks ``http.client`` directly: it never reads proxy variables, never follows a
redirect and never retries. TLS uses the default context, which verifies the certificate and
the host name; there is no option to turn that off. Error bodies are never read into messages.
"""

from __future__ import annotations

import http.client
import json
import ssl
import time
from collections.abc import Mapping
from typing import Any, Final, cast

from gazua.http import RUN_HEADER, user_agent
from gazua.http.models import MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, Endpoint
from gazua.integration.errors import GazuaBlockedError

MIN_SOCKET_SECONDS: Final = 0.05
_READ_CHUNK: Final = 64 * 1024


class HttpAttemptFailed(GazuaBlockedError):
    """The attempt cannot go on; ``reason`` is the public ``http_*`` or ``otel_*`` code."""


class HttpRateLimited(Exception):
    """The endpoint answered 429. ``retry_after`` is the delay it asked for, when readable."""

    def __init__(self, retry_after: float | None) -> None:
        self.retry_after = retry_after
        super().__init__("http_rate_limited")


def _retry_after(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        seconds = float(value.strip())
    except ValueError:
        return None
    return seconds if 0 <= seconds <= 3600 else None


def request_body(message: str, attempt_id: str) -> bytes:
    body = json.dumps({"message": message, "run_id": attempt_id}, ensure_ascii=False)
    encoded = body.encode("utf-8")
    if len(encoded) > MAX_REQUEST_BYTES:
        raise HttpAttemptFailed("http_request_limit")
    return encoded


def request_headers(
    static: Mapping[str, str], attempt_id: str, extra: Mapping[str, str] | None = None
) -> dict[str, str]:
    """Static headers first, then Gazua's, which the configuration can never replace."""
    headers = dict(static)
    headers.update(
        {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": user_agent(),
            RUN_HEADER: attempt_id,
        }
    )
    if extra:
        headers.update(extra)
    return headers


def _read_limited(response: http.client.HTTPResponse) -> bytes:
    declared = response.getheader("Content-Length")
    if declared is not None and declared.strip().isdigit() and int(declared) > MAX_RESPONSE_BYTES:
        raise HttpAttemptFailed("http_response_limit")
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = response.read(_READ_CHUNK)
        if not chunk:
            break
        size += len(chunk)
        if size > MAX_RESPONSE_BYTES:
            raise HttpAttemptFailed("http_response_limit")
        chunks.append(chunk)
    return b"".join(chunks)


def parse_response(body: bytes) -> str:
    """The ``response`` text of a JSON object; anything else is an invalid response."""
    try:
        document: object = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise HttpAttemptFailed("http_response_invalid") from None
    if not isinstance(document, dict):
        raise HttpAttemptFailed("http_response_invalid")
    text = cast("dict[str, Any]", document).get("response")
    if not isinstance(text, str):
        raise HttpAttemptFailed("http_response_invalid")
    return text


class HttpClient:
    """Sends the turns of one attempt to one endpoint, one connection per request."""

    def __init__(
        self,
        endpoint: Endpoint,
        static_headers: Mapping[str, str],
        attempt_id: str,
        *,
        deadline: float,
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.attempt_id = attempt_id
        self.deadline = deadline
        self.headers = request_headers(static_headers, attempt_id, extra_headers)
        self.requests = 0

    def _connection(self, timeout: float) -> http.client.HTTPConnection:
        endpoint = self.endpoint
        if endpoint.scheme == "https":
            return http.client.HTTPSConnection(
                endpoint.host,
                endpoint.port,
                timeout=timeout,
                context=ssl.create_default_context(),
            )
        return http.client.HTTPConnection(endpoint.host, endpoint.port, timeout=timeout)

    def send(self, message: str) -> str:
        """Posts one turn and returns the endpoint's text response.

        A lost connection or a timeout after the request may have changed the endpoint, so the
        request is never repeated here.
        """
        body = request_body(message, self.attempt_id)
        remaining = self.deadline - time.monotonic()
        if remaining <= MIN_SOCKET_SECONDS:
            raise HttpAttemptFailed("http_transport_lost")
        connection = self._connection(remaining)
        self.requests += 1
        try:
            connection.request("POST", self.endpoint.target, body=body, headers=self.headers)
            response = connection.getresponse()
            status = response.status
            if 300 <= status < 400:
                raise HttpAttemptFailed("http_redirect_refused")
            if status == 429:
                raise HttpRateLimited(_retry_after(response.getheader("Retry-After")))
            if 400 <= status < 500:
                raise HttpAttemptFailed("http_client_error")
            if status >= 500:
                raise HttpAttemptFailed("http_server_error")
            if not 200 <= status < 300:
                raise HttpAttemptFailed("http_response_invalid")
            return parse_response(_read_limited(response))
        except ssl.SSLError:
            raise HttpAttemptFailed("http_tls_failed") from None
        except (OSError, http.client.HTTPException):
            raise HttpAttemptFailed("http_transport_lost") from None
        finally:
            connection.close()


__all__ = [
    "HttpAttemptFailed",
    "HttpClient",
    "HttpRateLimited",
    "parse_response",
    "request_body",
    "request_headers",
]
