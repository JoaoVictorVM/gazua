"""Endpoint parsing, exact allowlist matching, transport and static header rules."""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gazua.config.models import GazuaConfig
from gazua.diagnostics import ConfigError
from gazua.http.models import EndpointError, header_problem, parse_endpoint
from gazua.http.policy import allowed, check_destination


def _config(endpoint: str, hosts: list[str] | None = None, **http: Any) -> GazuaConfig:
    document: dict[str, Any] = {
        "schema_version": 1,
        "http": {"endpoint": endpoint, "real_side_effects": "i_understand", **http},
    }
    if hosts is not None:
        document["allowed_targets"] = hosts
    return GazuaConfig.model_validate(document)


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://user:pass@agent.test.example/x",
        "https://agent.test.example/x#fragment",
        "https://*.test.example/x",
        "ftp://agent.test.example/x",
        "https:///x",
        "agent.test.example/x",
        "https://agent.test.example:0/x",
        "https://agent test.example/x",
        "https://ágent.test.example/x",
        "https://agent.test.example:99999/x",
    ],
)
def test_ambiguous_endpoints_are_refused(endpoint: str) -> None:
    with pytest.raises(EndpointError):
        parse_endpoint(endpoint)
    with pytest.raises(ValueError, match="endpoint"):
        _config(endpoint)


def test_exact_allowlist_rejects_suffix_userinfo_and_wildcard() -> None:
    target = parse_endpoint("https://agent.test.example/api?x=1")
    assert target.origin == "https://agent.test.example"
    assert target.target == "/api?x=1"
    assert allowed(target, ["agent.test.example"])
    assert allowed(target, ["AGENT.test.example"])
    for near in (["test.example"], ["agent.test.example.evil"], ["gent.test.example"], ["*"]):
        assert not allowed(target, near)
    with pytest.raises(ConfigError) as caught:
        check_destination(_config("https://agent.test.example.evil/x", ["agent.test.example"]))
    assert caught.value.diagnostics[0].code == "http_target_not_allowed"
    assert "agent.test.example.evil" in caught.value.diagnostics[0].message
    # The default allowlist is the loopback.
    with pytest.raises(ConfigError):
        check_destination(_config("https://agent.test.example/x"))


def test_remote_http_requires_tls_and_loopback_allows_http() -> None:
    for endpoint in ("http://localhost:8080/a", "http://127.0.0.1/a", "http://[::1]:9/a"):
        assert check_destination(_config(endpoint)).loopback
    with pytest.raises(ConfigError) as caught:
        check_destination(_config("http://agent.test.example/a", ["agent.test.example"]))
    assert caught.value.diagnostics[0].code == "http_tls_required"
    assert (
        check_destination(_config("https://agent.test.example/a", ["agent.test.example"])).scheme
        == "https"
    )
    # A loopback alias outside the exact list is not loopback.
    with pytest.raises(ConfigError):
        check_destination(_config("http://127.0.0.2/a", ["127.0.0.2"]))


def test_ipv6_origin_keeps_brackets_and_default_ports_are_left_out() -> None:
    assert parse_endpoint("http://[::1]:8080/x").origin == "http://[::1]:8080"
    assert parse_endpoint("https://agent.test.example:443/x").origin == "https://agent.test.example"
    assert parse_endpoint("HTTP://LOCALHOST/").host == "localhost"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("User-Agent", "spoof"),
        ("x-gazua-run", "other"),
        ("Authorization", "Bearer x"),
        ("Cookie", "a=b"),
        ("X-Gazua-Trace-Token", "t"),
        ("Bad Name", "v"),
        ("X-Ok", "line\r\nInjected: yes"),
        ("X-Ok", "nul\x00"),
        ("X-Ok", "x" * 1025),
    ],
)
def test_reserved_or_unsafe_headers_are_refused(name: str, value: str) -> None:
    assert header_problem(name, value) is not None
    with pytest.raises(ValueError, match=r"[Hh]eader"):
        _config("http://localhost/a", headers={name: value})


def test_static_headers_are_limited_and_unique() -> None:
    assert header_problem("X-Test-Tenant", "gazua-fixture") is None
    with pytest.raises(ValueError, match="32"):
        _config("http://localhost/a", headers={f"X-H{index}": "v" for index in range(33)})
    with pytest.raises(ValueError, match="unique"):
        _config("http://localhost/a", headers={"X-A": "1", "x-a": "2"})


@given(st.text(max_size=40))
def test_header_values_never_carry_line_breaks(value: str) -> None:
    problem = header_problem("X-Test", value)
    if any(char in value for char in "\r\n\x00"):
        assert problem is not None


@given(
    host=st.from_regex(r"[a-z][a-z0-9-]{0,10}(\.[a-z][a-z0-9-]{0,10}){0,3}", fullmatch=True),
    prefix=st.from_regex(r"[a-z0-9-]{1,6}\.", fullmatch=True),
    suffix=st.from_regex(r"\.[a-z]{1,6}", fullmatch=True),
)
def test_allowlist_is_exact_for_any_host(host: str, prefix: str, suffix: str) -> None:
    target = parse_endpoint(f"https://{host}/x")
    assert allowed(target, [host.upper()])
    assert not allowed(parse_endpoint(f"https://{prefix}{host}/x"), [host])
    assert not allowed(parse_endpoint(f"https://{host}{suffix}/x"), [host])
