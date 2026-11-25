"""Shared helpers of the CI tests: run documents, event payloads and a fake GitHub API.

The fake API keeps comments in memory, records every request and never touches the network.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from baseline_factory import baseline, entry, reference
from report_factory import document

from gazua.ci.github import Request, Response
from gazua.ci.models import COMMENT_MARKER
from gazua.reports.models import RunDocument

ROOT = Path(__file__).resolve().parents[2]
SARIF_SCHEMA = ROOT / "tests" / "support" / "ci" / "sarif-schema-2.1.0.json"
FIXTURES = ROOT / "tests" / "support" / "ci"
REPOSITORY = "owner/repo"
API = "https://api.github.test"
BOT = "github-actions[bot]"


def plain_run(**options: Any) -> RunDocument:
    """A tools run with one proven, gated IDOR finding and no baseline."""
    return document(**options)


def run_with_baseline(status: str = "open") -> RunDocument:
    """The same run compared with a baseline that holds its finding as ``status``."""
    first = plain_run()
    [finding] = first.findings
    keys = [first.scenario(key).baseline_reference for key in finding.scenarios]
    references = sorted({(item.scenario_digest, item.language) for item in keys})
    accepted = baseline(
        entry(
            finding.id,
            status=status,
            scenarios=[reference(digest, language) for digest, language in references],
        )
    )
    return plain_run(baseline=accepted, exit_code=0 if status == "open" else 1)


def event_file(folder: Path, *, head: str | None = REPOSITORY, number: Any = 7) -> Path:
    payload: dict[str, Any] = {"repository": {"full_name": REPOSITORY}}
    pull: dict[str, Any] = {"number": number}
    if head is not None:
        pull["head"] = {"repo": {"full_name": head}}
    payload["pull_request"] = pull
    path = folder / "event.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def environment(folder: Path, event: str = "pull_request", **extra: str) -> dict[str, str]:
    """The Action's variables; an event file the test already wrote is kept."""
    path = folder / "event.json"
    values = {
        "GITHUB_EVENT_NAME": event,
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_EVENT_PATH": str(path if path.is_file() else event_file(folder)),
        "GITHUB_WORKSPACE": str(folder),
        "GAZUA_CI_CONTRACT": "1",
    }
    values.update(extra)
    return values


@dataclass
class FakeGitHub:
    """Issue comments of one pull request, with pagination, permissions and failures."""

    comments: list[dict[str, Any]] = field(default_factory=list[dict[str, Any]])
    requests: list[Request] = field(default_factory=list[Request])
    page_size: int = 100
    status: dict[str, int] = field(default_factory=dict[str, int])
    next_id: int = 1000
    leak: str = "SERVER-SIDE-DETAIL token=ghp_" + "x" * 36

    def add(self, body: str, login: str = BOT) -> int:
        self.next_id += 1
        self.comments.append({"id": self.next_id, "user": {"login": login}, "body": body})
        return self.next_id

    def owned(self) -> list[dict[str, Any]]:
        return [
            item
            for item in self.comments
            if item["user"]["login"] == BOT and item["body"].startswith(COMMENT_MARKER)
        ]

    def __call__(self, request: Request) -> Response:
        self.requests.append(request)
        path = request.url.removeprefix(API)
        forced = self.status.get(request.method)
        if forced is not None:
            return Response(forced, {}, json.dumps({"message": self.leak}).encode())
        if path == "/user":
            return Response(403, {}, b'{"message": "Resource not accessible by integration"}')
        base = f"/repos/{REPOSITORY}/issues/7/comments"
        if request.method == "GET" and path.startswith(base):
            page = 1
            if "&page=" in path:
                page = int(path.rsplit("&page=", 1)[1])
            start = (page - 1) * self.page_size
            chunk = self.comments[start : start + self.page_size]
            headers: dict[str, str] = {}
            if start + self.page_size < len(self.comments):
                headers["Link"] = f'<{API}{base}?per_page=100&page={page + 1}>; rel="next"'
            return Response(200, headers, json.dumps(chunk).encode())
        if request.method == "POST" and path == base:
            body = json.loads(request.body or b"{}")["body"]
            number = self.add(body)
            return Response(201, {}, json.dumps({"id": number}).encode())
        prefix = f"/repos/{REPOSITORY}/issues/comments/"
        if path.startswith(prefix):
            number = int(path.removeprefix(prefix))
            found = next((item for item in self.comments if item["id"] == number), None)
            if found is None:
                return Response(404, {}, b"{}")
            if request.method == "PATCH":
                found["body"] = json.loads(request.body or b"{}")["body"]
                return Response(200, {}, json.dumps(found).encode())
            if request.method == "DELETE":
                self.comments.remove(found)
                return Response(204, {}, b"")
        return Response(404, {}, b"{}")
