import pytest
from ci_support import API, BOT, REPOSITORY, FakeGitHub

from gazua.ci.github import CommentError, GitHubComments, Request, Response
from gazua.ci.models import COMMENT_MARKER

BODY = COMMENT_MARKER + "\n## Gazua security tests\n\nv2\n"
OLD = COMMENT_MARKER + "\n## Gazua security tests\n\nv1\n"
TOKEN = "ghs_" + "t" * 36


def _client(fake: FakeGitHub) -> GitHubComments:
    return GitHubComments(REPOSITORY, 7, TOKEN, api_url=API, transport=fake)


def test_create_when_owned_comment_absent() -> None:
    fake = FakeGitHub()
    fake.add("A user's review comment", login="someone")

    result = _client(fake).publish(BODY)

    assert result.action == "created"
    assert [item["body"] for item in fake.owned()] == [BODY]
    request = fake.requests[-1]
    assert request.method == "POST"
    assert request.headers["X-GitHub-Api-Version"] == "2026-03-10"
    assert request.headers["Accept"] == "application/vnd.github+json"
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"


def test_update_owned_comment_without_duplicate() -> None:
    fake = FakeGitHub()
    number = fake.add(OLD)

    first = _client(fake).publish(BODY)
    second = _client(fake).publish(BODY)

    assert (first.action, first.comment_id) == ("updated", number)
    assert second.action == "unchanged"
    assert [item["body"] for item in fake.owned()] == [BODY]
    assert [item.method for item in fake.requests].count("PATCH") == 1


def test_user_marker_is_not_edited() -> None:
    fake = FakeGitHub()
    fake.add(OLD, login="someone")

    result = _client(fake).publish(BODY)

    assert result.action == "created"
    assert fake.comments[0]["body"] == OLD
    assert not any(item.method in ("PATCH", "DELETE") for item in fake.requests)


def test_owned_duplicates_are_removed() -> None:
    fake = FakeGitHub()
    canonical = fake.add(OLD)
    fake.add(OLD)
    fake.add(BODY)
    fake.add(OLD, login="someone")

    result = _client(fake).publish(BODY)

    assert (result.action, result.comment_id, result.removed) == ("updated", canonical, 2)
    assert [item["id"] for item in fake.owned()] == [canonical]
    assert len(fake.comments) == 2


@pytest.mark.parametrize(
    ("method", "status", "code"),
    [
        ("GET", 401, "ci_comment_permission"),
        ("GET", 404, "ci_comment_permission"),
        ("POST", 403, "ci_comment_permission"),
        ("POST", 410, "ci_comment_permission"),
        ("POST", 422, "ci_comment_failed"),
        ("POST", 429, "ci_comment_failed"),
        ("POST", 500, "ci_comment_failed"),
    ],
)
def test_permission_failure_does_not_expose_response(
    method: str, status: int, code: str, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = FakeGitHub(status={method: status})

    with pytest.raises(CommentError) as caught:
        _client(fake).publish(BODY)

    assert caught.value.code == code
    assert str(caught.value) == code
    assert fake.leak not in repr(caught.value)
    assert TOKEN not in repr(_client(fake))
    output = capsys.readouterr()
    assert TOKEN not in output.out + output.err


def test_transport_failure_and_foreign_pagination_are_refused() -> None:
    def broken(request: Request) -> Response:
        raise TimeoutError(request.url)

    with pytest.raises(CommentError) as caught:
        GitHubComments(REPOSITORY, 7, TOKEN, api_url=API, transport=broken).publish(BODY)
    assert caught.value.code == "ci_comment_failed"

    seen: list[str] = []

    def hostile(request: Request) -> Response:
        seen.append(request.url)
        if request.url.endswith("/user"):
            return Response(403, {}, b"{}")
        link = '<https://evil.test/steal?per_page=100&page=2>; rel="next"'
        return Response(200, {"Link": link}, b"[]")

    with pytest.raises(CommentError):
        GitHubComments(REPOSITORY, 7, TOKEN, api_url=API, transport=hostile).publish(BODY)
    assert not any("evil.test" in url for url in seen)


def test_insecure_api_url_and_missing_token_are_refused() -> None:
    with pytest.raises(CommentError):
        GitHubComments(REPOSITORY, 7, TOKEN, api_url="http://api.github.test")
    with pytest.raises(CommentError) as caught:
        GitHubComments(REPOSITORY, 7, "", api_url=API)
    assert caught.value.code == "ci_comment_permission"


def test_identity_from_user_endpoint_is_used() -> None:
    fake = FakeGitHub()
    fake.add(OLD, login="gazua-app[bot]")

    def as_app(request: Request) -> Response:
        if request.url.endswith("/user"):
            return Response(200, {}, b'{"login": "gazua-app[bot]"}')
        return fake(request)

    result = GitHubComments(REPOSITORY, 7, TOKEN, api_url=API, transport=as_app).publish(BODY)

    assert result.action == "updated"
    assert BOT not in [item["user"]["login"] for item in fake.comments]
