"""The single pull request comment, through the GitHub REST API.

Only comments written by the authenticated identity whose body starts with the versioned
marker are owned. The oldest owned comment is canonical: it is created when absent, updated
only when its bytes differ, and other owned copies are removed. A user's comment carrying the
same marker is never touched. Errors become fixed codes; no response body, URL or token is
ever printed.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Final, Literal, cast
from urllib.parse import urlsplit

from gazua.ci.models import COMMENT_MARKER

API_VERSION: Final = "2026-03-10"
DEFAULT_API: Final = "https://api.github.com"
ACTIONS_BOT: Final = "github-actions[bot]"
PAGE_SIZE: Final = 100
MAX_PAGES: Final = 10
MAX_RESPONSE_BYTES: Final = 8 * 1024 * 1024
MAX_RESPONSE_DEPTH: Final = 32
TIMEOUT_SECONDS: Final = 30.0
_NEXT: Final = re.compile(r'<([^<>\s]+)>\s*;\s*rel="next"')
PERMISSION_STATUSES: Final = frozenset({401, 403, 404, 410})


@dataclass(frozen=True, slots=True)
class Request:
    method: Literal["GET", "POST", "PATCH", "DELETE"]
    url: str
    headers: dict[str, str]
    body: bytes | None = None


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    headers: dict[str, str]
    body: bytes


Transport = Callable[[Request], Response]


class CommentError(Exception):
    """The comment could not be published. ``code`` is safe to print."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(slots=True)
class CommentResult:
    action: Literal["created", "updated", "unchanged", "skipped"]
    comment_id: int | None = None
    removed: int = 0
    warnings: list[str] = field(default_factory=list[str])


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # A redirect would resend the token to a host this module never checked.
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def urllib_transport(request: Request) -> Response:
    """The default transport: HTTPS with the system's verification, no redirects."""
    opener = urllib.request.build_opener(_NoRedirect)
    prepared = urllib.request.Request(  # noqa: S310
        request.url, data=request.body, headers=request.headers, method=request.method
    )
    try:
        with opener.open(prepared, timeout=TIMEOUT_SECONDS) as answer:
            body = answer.read(MAX_RESPONSE_BYTES + 1)
            return Response(answer.status, dict(answer.headers.items()), body)
    except urllib.error.HTTPError as error:
        status = error.code
        headers = dict(error.headers.items())
        error.close()
        return Response(status, headers, b"")
    except (urllib.error.URLError, TimeoutError, OSError):
        raise CommentError("ci_comment_failed") from None


def _depth(value: Any) -> int:
    deepest = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, level = stack.pop()
        deepest = max(deepest, level)
        if isinstance(item, dict):
            stack.extend((child, level + 1) for child in cast("dict[str, Any]", item).values())
        elif isinstance(item, list):
            stack.extend((child, level + 1) for child in cast("list[Any]", item))
    return deepest


def _json(body: bytes) -> Any:
    if len(body) > MAX_RESPONSE_BYTES:
        raise CommentError("ci_comment_failed")
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise CommentError("ci_comment_failed") from None
    if _depth(data) > MAX_RESPONSE_DEPTH:
        raise CommentError("ci_comment_failed")
    return data


def _field(data: Any, name: str) -> Any:
    return cast("dict[str, Any]", data).get(name) if isinstance(data, dict) else None


def _header(headers: dict[str, str], name: str) -> str:
    wanted = name.lower()
    return next((value for key, value in headers.items() if key.lower() == wanted), "")


@dataclass(frozen=True, slots=True)
class _Owned:
    id: int
    body: str


class GitHubComments:
    """Comment operations on one pull request, with the token kept inside this object."""

    def __init__(
        self,
        repository: str,
        pull_request: int,
        token: str,
        *,
        api_url: str = DEFAULT_API,
        transport: Transport | None = None,
    ) -> None:
        parts = urlsplit(api_url)
        if parts.scheme != "https" or not parts.netloc or parts.query or parts.fragment:
            raise CommentError("ci_comment_failed")
        if not token:
            raise CommentError("ci_comment_permission")
        self._base = api_url.rstrip("/")
        self._origin = (parts.scheme, parts.netloc)
        self._repository = repository
        self._pull_request = pull_request
        self._token = token
        self._transport = transport or urllib_transport

    def __repr__(self) -> str:
        return f"GitHubComments({self._repository}#{self._pull_request})"

    def _send(
        self, method: Literal["GET", "POST", "PATCH", "DELETE"], url: str, body: Any = None
    ) -> Response:
        parts = urlsplit(url)
        if (parts.scheme, parts.netloc) != self._origin:
            raise CommentError("ci_comment_failed")
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "gazua-ci",
        }
        payload = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            payload = json.dumps(body).encode("utf-8")
        try:
            return self._transport(Request(method, url, headers, payload))
        except CommentError:
            raise
        except Exception:  # noqa: BLE001
            raise CommentError("ci_comment_failed") from None

    @staticmethod
    def _check(response: Response, expected: int) -> None:
        if response.status == expected:
            return
        limited = _header(response.headers, "X-RateLimit-Remaining") == "0"
        if response.status == 429 or (response.status == 403 and limited):
            raise CommentError("ci_comment_failed")
        if response.status in PERMISSION_STATUSES:
            raise CommentError("ci_comment_permission")
        raise CommentError("ci_comment_failed")

    def identity(self) -> str:
        """The login the token writes as; the workflow token cannot ask, so it is the bot."""
        response = self._send("GET", f"{self._base}/user")
        if response.status != 200:
            return ACTIONS_BOT
        data = _json(response.body)
        login = _field(data, "login")
        return login if isinstance(login, str) and login else ACTIONS_BOT

    def owned(self, login: str) -> tuple[list[_Owned], bool]:
        """Owned comments, oldest first, and whether every page could be read."""
        url: str | None = (
            f"{self._base}/repos/{self._repository}/issues/{self._pull_request}/comments"
            f"?per_page={PAGE_SIZE}"
        )
        found: list[_Owned] = []
        pages = 0
        while url is not None:
            if pages == MAX_PAGES:
                return sorted(found, key=lambda item: item.id), False
            response = self._send("GET", url)
            self._check(response, 200)
            data = _json(response.body)
            if not isinstance(data, list):
                raise CommentError("ci_comment_failed")
            for item in cast("list[Any]", data):
                if not isinstance(item, dict):
                    continue
                comment = cast("dict[str, Any]", item)
                user: Any = comment.get("user")
                author = _field(user, "login")
                body, number = comment.get("body"), comment.get("id")
                if (
                    author == login
                    and isinstance(body, str)
                    and body.startswith(COMMENT_MARKER)
                    and type(number) is int
                ):
                    found.append(_Owned(number, body))
            pages += 1
            match = _NEXT.search(_header(response.headers, "Link"))
            url = match.group(1) if match else None
        return sorted(found, key=lambda item: item.id), True

    def publish(self, body: str) -> CommentResult:
        """Creates, updates or keeps the single owned comment, then removes owned extras."""
        if not body.startswith(COMMENT_MARKER):
            raise CommentError("ci_comment_invalid")
        login = self.identity()
        owned, complete = self.owned(login)
        warnings: list[str] = []
        if not owned:
            if not complete:
                return CommentResult("skipped", warnings=["ci_comment_pagination_limit"])
            response = self._send(
                "POST",
                f"{self._base}/repos/{self._repository}/issues/{self._pull_request}/comments",
                {"body": body},
            )
            self._check(response, 201)
            data = _json(response.body)
            number = _field(data, "id")
            return CommentResult("created", number if type(number) is int else None)
        canonical, extras = owned[0], owned[1:]
        action: Literal["updated", "unchanged"] = "unchanged"
        if canonical.body != body:
            response = self._send(
                "PATCH",
                f"{self._base}/repos/{self._repository}/issues/comments/{canonical.id}",
                {"body": body},
            )
            self._check(response, 200)
            action = "updated"
        removed = 0
        for extra in extras:
            response = self._send(
                "DELETE", f"{self._base}/repos/{self._repository}/issues/comments/{extra.id}"
            )
            if response.status == 204:
                removed += 1
            elif "ci_comment_duplicate_kept" not in warnings:
                warnings.append("ci_comment_duplicate_kept")
        if not complete:
            warnings.append("ci_comment_pagination_limit")
        return CommentResult(action, canonical.id, removed, warnings)
