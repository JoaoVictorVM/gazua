"""Runs Gazua in this process under observation and writes what it did to a JSON report.

Usage: app_spy.py REPORT_PATH (control | import | load CONFIG | cli [ARGS...])
"""

import contextlib
import json
import os
import socket
import sys
from pathlib import Path
from typing import Any

report: dict[str, Any] = {
    "network": [],
    "credential_reads": [],
    "environment_listed": False,
    "opened_paths": [],
    "exit_code": None,
}


def is_credential_name(name: object) -> bool:
    if not isinstance(name, str):
        return False
    upper = name.upper()
    return upper.endswith(("_API_KEY", "_TOKEN", "_SECRET", "_PASSWORD")) or upper in {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "GOOGLE_APPLICATION_CREDENTIALS",
    }


class SpyEnviron(type(os.environ)):
    def __getitem__(self, key: str) -> str:
        if is_credential_name(key):
            report["credential_reads"].append(key)
        return super().__getitem__(key)

    def __iter__(self):
        report["environment_listed"] = True
        return super().__iter__()


def audit(event: str, args: tuple[object, ...]) -> None:
    if event == "open" and isinstance(args[0], str):
        report["opened_paths"].append(args[0])
    if event.startswith(("socket.", "http.", "urllib.", "ftplib.", "smtplib.")):
        report["network"].append(event)


def attempt_forbidden_actions() -> None:
    """Positive control: proves that the spy sees what the real tests expect to be absent."""
    os.environ.get("OPENAI_API_KEY")
    socket.getaddrinfo("localhost", 9)
    with socket.socket() as probe:
        probe.settimeout(1)
        with contextlib.suppress(OSError):
            probe.connect(("127.0.0.1", 9))


def run_target(mode: str, arguments: list[str]) -> int:
    if mode == "control":
        attempt_forbidden_actions()
        return 0
    if mode == "import":
        __import__("gazua")
        __import__("gazua.cli")
        return 0
    if mode == "load":
        from gazua.config import load_config

        load_config(arguments[0])
        return 0
    from gazua._bootstrap import main

    sys.argv = ["gazua", *arguments]
    try:
        return main()
    except SystemExit as exit_request:
        return exit_request.code if isinstance(exit_request.code, int) else 1


if __name__ == "__main__":
    report_path, target_mode, *target_arguments = sys.argv[1:]
    os.environ.__class__ = SpyEnviron
    sys.addaudithook(audit)
    report["exit_code"] = run_target(target_mode, target_arguments)
    Path(report_path).write_text(json.dumps(report), encoding="utf-8")
