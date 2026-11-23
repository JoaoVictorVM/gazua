"""The destination gate: no request leaves for a host, transport or configuration not allowed.

Each negative case has a positive control showing that the same spy would have seen a request.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from http_support import AgentServer, HttpProject, SpyServer

from gazua.diagnostics import ConfigError

PROXY_VARIABLES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy")


def test_disallowed_host_receives_no_request_even_with_environment_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SpyServer() as target, SpyServer() as proxy:
        project = HttpProject(tmp_path, target.url(host="localhost"), traces=False)
        project.update(allowed_targets=["127.0.0.1"])
        for name in PROXY_VARIABLES:
            monkeypatch.setenv(name, proxy.url("/"))
        monkeypatch.setenv("NO_PROXY", "")
        for name in ("GAZUA_ALLOWED_TARGETS", "GAZUA_HTTP_ALLOW_ANY", "GAZUA_ALLOW_REMOTE"):
            monkeypatch.setenv(name, "localhost")

        with pytest.raises(ConfigError) as caught:
            project.run_agent()

        [diagnostic] = caught.value.diagnostics
        assert diagnostic.code == "http_target_not_allowed"
        assert diagnostic.message.startswith("Host localhost is not in allowed_targets")
        result = project.cli("run", "--agent", "--mold", "secret-04")
        assert result.returncode == 2
        assert "Host localhost is not in allowed_targets" in result.stderr
        assert "Traceback" not in result.stderr
        assert target.count == 0
        assert proxy.count == 0

        # Positive control: the same spy, allowed, receives the attack, and the inherited
        # proxy is still never used.
        project.update(allowed_targets=["localhost", "127.0.0.1"])
        project.update(http={**project.config["http"], "endpoint": target.url()})
        project.authorize()
        project.run_agent(["secret-04"])
        assert target.count >= 1
        assert proxy.count == 0


def test_remote_http_needs_tls_before_any_request(tmp_path: Path) -> None:
    with SpyServer() as target:
        project = HttpProject(tmp_path, f"http://agent.test.example:{target.port}/x", traces=False)
        project.update(allowed_targets=["agent.test.example"])
        project.authorize()

        with pytest.raises(ConfigError) as caught:
            project.run_agent()

        assert caught.value.diagnostics[0].code == "http_tls_required"
        assert target.count == 0


def test_missing_real_side_effects_refuses_before_network(tmp_path: Path) -> None:
    with AgentServer() as target:
        project = HttpProject(tmp_path, target.url(), traces=False)
        http: dict[str, Any] = dict(project.config["http"])
        http.pop("real_side_effects")
        project.update(http=http)
        # A receipt for this exact configuration is not enough on its own.
        project.authorize()

        with pytest.raises(ConfigError) as caught:
            project.run_agent()
        result = project.cli("run", "--agent")

        assert caught.value.diagnostics[0].code == "http_real_side_effects_missing"
        assert result.returncode == 2
        assert "no dry-run" in result.stderr
        assert "real_side_effects: i_understand" in result.stderr
        assert target.count == 0


def test_missing_or_stale_receipt_refuses_before_network(tmp_path: Path) -> None:
    with AgentServer() as target:
        project = HttpProject(tmp_path, target.url(), traces=False)
        (tmp_path / ".gazua" / "authorization-v1.json").unlink()

        with pytest.raises(ConfigError) as missing:
            project.run_agent()

        project.authorize()
        project.update(http={**project.config["http"], "headers": {"X-Test-Tenant": "other"}})
        with pytest.raises(ConfigError) as stale:
            project.run_agent()

        assert missing.value.diagnostics[0].code == "http_authorization_missing"
        assert stale.value.diagnostics[0].code == "http_authorization_missing"
        assert "gazua init --http" in stale.value.diagnostics[0].message
        assert target.count == 0


def test_tools_mode_refuses_an_http_target(tmp_path: Path) -> None:
    with AgentServer() as target:
        project = HttpProject(tmp_path, target.url(), traces=False)

        result = project.cli("run", "--tools")

        assert result.returncode == 2
        assert "--tools needs direct tool access" in result.stderr
        assert target.count == 0
