"""The demo reaches nothing outside the machine and reads no credential, in any process."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from demo_support import SPY_SITE, is_loopback

REMOTE = re.compile(r"""(?:src|href|action)\s*=\s*["']?\s*(?:https?:)?//""", re.IGNORECASE)


def test_spy_sees_external_lookups_and_credential_reads(
    tmp_path: Path, clean_environment: Any
) -> None:
    code = (
        "import os, socket\n"
        "os.environ.get('OPENAI_API_KEY')\n"
        "try:\n"
        "    socket.getaddrinfo('gazua-spy-control.example', 443)\n"
        "except OSError:\n"
        "    pass\n"
    )
    env = {
        **clean_environment(),
        "PYTHONPATH": str(SPY_SITE),
        "GAZUA_DEMO_SPY": str(tmp_path),
        "OPENAI_API_KEY": "sentinel-not-a-real-key",
    }
    subprocess.run([sys.executable, "-c", code], env=env, check=True, timeout=60)

    events = "".join(path.read_text(encoding="utf-8") for path in tmp_path.glob("*.jsonl"))
    assert "gazua-spy-control.example" in events
    assert '"credential_read"' in events
    assert not is_loopback("'gazua-spy-control.example'")
    assert is_loopback("('127.0.0.1', 51234)")
    assert is_loopback("('::1', 51234, 0, 0)")


def test_parent_and_workers_make_no_external_connection(spied_demo: Any) -> None:
    events = spied_demo.spy_events()

    assert spied_demo.result.returncode == 1, spied_demo.result.stderr
    processes = {event["pid"] for event in events if event["kind"] == "process"}
    # The supervisor, the discovery workers and one worker per execution of both modes.
    assert len(processes) > 50
    external = [
        event
        for event in events
        if event["kind"] == "network" and not is_loopback(event["address"])
    ]
    assert external == []


def test_demo_never_reads_provider_credentials(spied_demo: Any) -> None:
    reads = [event for event in spied_demo.spy_events() if event["kind"] == "credential_read"]

    assert reads == []


def test_report_has_no_remote_resources(spied_demo: Any) -> None:
    pages = [spied_demo.workspace / "index.html", *spied_demo.workspace.rglob("report.html")]

    assert len(pages) >= 4
    for page in pages:
        html = page.read_text(encoding="utf-8")
        assert "default-src 'none'" in html.replace("&#39;", "'"), page
        assert not REMOTE.search(html), page
        assert "@import" not in html
        assert not re.search(r"url\(\s*['\"]?(?:https?:)?//", html)
