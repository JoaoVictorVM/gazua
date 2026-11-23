"""``gazua init --http``: a conservative file and a receipt, only after a typed confirmation."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from http_support import SpyServer
from typer.testing import CliRunner

from gazua import cli
from gazua.config.loader import load_config
from gazua.http.authorization import check_receipt, receipt_path


def _no_network(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    attempts: list[Any] = []

    def refuse(*args: Any, **kwargs: Any) -> Any:
        attempts.append(args)
        raise AssertionError("init opened a connection")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    return attempts


def _init(directory: Path, url: str, typed: str) -> Any:
    return CliRunner().invoke(cli.app, ["init", str(directory), "--http", url], input=typed + "\n")


def test_init_records_authorization_without_contacting_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SpyServer() as target:
        url = target.url("/api/test-message")
        monkeypatch.setattr(cli, "_interactive", lambda: True)
        attempts = _no_network(monkeypatch)
        phrase = f"I am authorized to test http://127.0.0.1:{target.port}"

        result = _init(tmp_path, url, phrase)

        assert result.exit_code == 0, result.output
        assert attempts == []
        assert target.count == 0
    assert "no dry-run" in result.output
    assert f"Origin: http://127.0.0.1:{target.port}" in result.output
    loaded = load_config(tmp_path / "gazua.yaml").config
    assert loaded.http is not None
    assert loaded.http.endpoint == url
    assert loaded.http.real_side_effects == "i_understand"
    assert loaded.allowed_targets == ["localhost", "127.0.0.1", "::1"]
    assert loaded.traces is None
    check_receipt(tmp_path, loaded)
    stored = receipt_path(tmp_path).read_text(encoding="utf-8")
    assert phrase not in stored
    assert set(json.loads(stored)) == {
        "schema_version",
        "origin",
        "config_hash",
        "confirmed_at",
        "authorized",
    }
    assert (tmp_path / ".gitignore").read_bytes() == b".gazua/\n"


def test_remote_host_is_added_explicitly_and_needs_tls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    _no_network(monkeypatch)

    plain = _init(tmp_path, "http://agent.test.example/api", "anything")
    assert plain.exit_code == 2
    assert not (tmp_path / "gazua.yaml").exists()

    secure = _init(
        tmp_path,
        "https://agent.test.example/api",
        "I am authorized to test https://agent.test.example",
    )
    assert secure.exit_code == 0, secure.output
    loaded = load_config(tmp_path / "gazua.yaml").config
    assert loaded.allowed_targets == ["agent.test.example"]


def test_abbreviated_or_non_interactive_confirmation_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = "http://127.0.0.1:8080/api"
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    for typed in ("yes", "y", "I am authorized", "i am authorized to test http://127.0.0.1:8080x"):
        result = _init(tmp_path, url, typed)
        assert result.exit_code == 2
        assert not (tmp_path / "gazua.yaml").exists()
        assert not receipt_path(tmp_path).exists()

    piped = subprocess.run(
        [sys.executable, "-m", "gazua", "init", str(tmp_path), "--http", url],
        input="I am authorized to test http://127.0.0.1:8080\n",
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert piped.returncode == 2
    assert "interactive terminal" in piped.stderr
    assert not (tmp_path / "gazua.yaml").exists()
    assert not receipt_path(tmp_path).exists()


def test_reconfirming_keeps_the_file_and_replaces_the_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = "http://127.0.0.1:8080/api"
    phrase = "I am authorized to test http://127.0.0.1:8080"
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    assert _init(tmp_path, url, phrase).exit_code == 0
    config_path = tmp_path / "gazua.yaml"
    edited = config_path.read_text(encoding="utf-8").replace(
        "headers: {}", 'headers: {"X-Test-Tenant": "gazua-fixture"}'
    )
    config_path.write_text(edited, encoding="utf-8")
    from gazua.http.authorization import ReceiptError

    with pytest.raises(ReceiptError):
        check_receipt(tmp_path, load_config(config_path).config)

    again = _init(tmp_path, url, phrase)

    assert again.exit_code == 0, again.output
    assert "Kept" in again.output
    assert config_path.read_text(encoding="utf-8") == edited
    check_receipt(tmp_path, load_config(config_path).config)
    other = _init(tmp_path, "http://127.0.0.1:9090/api", "I am authorized to test x")
    assert other.exit_code == 2
    assert config_path.read_text(encoding="utf-8") == edited


def test_clean_preserves_the_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    assert (
        _init(
            tmp_path,
            "http://127.0.0.1:8080/api",
            "I am authorized to test http://127.0.0.1:8080",
        ).exit_code
        == 0
    )
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(cli.app, ["clean"])

    assert result.exit_code == 0
    assert receipt_path(tmp_path).is_file()
