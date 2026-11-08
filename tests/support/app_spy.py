"""Runs Gazua in this process under observation and writes what it did to a JSON report.

Usage: app_spy.py REPORT_PATH
    (control | import | load CONFIG | wrap [SESSION] | verdict | cli [ARGS...])
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


def run_wrapped_tools(arguments: list[str]) -> int:
    """Calls one real and one dry-run tool, inside the given session or outside of any."""
    if arguments:
        os.environ["GAZUA_SESSION"] = arguments[0]
    import gazua

    def read_note(name: str) -> str:
        return f"note {name}"

    @gazua.tool
    def send_email(to: str) -> str:
        return f"sent to {to}"

    read, send = gazua.wrap([read_note, send_email])
    report["results"] = [read("a"), send("b")]
    return 0


def run_verdicts() -> int:
    """Judges synthetic evidence for three signals, as a mode would after a run."""
    import gazua

    report["verdicts_on_import"] = sorted(name for name in sys.modules if "verdicts" in name)
    from verdict_factory import call, config, context, envelope, evidence, hit, record, sink
    from verdict_factory import summary as run_summary

    from gazua.verdicts.engine import VerdictCollector

    attacks = [
        context("forbidden_tool_call", key="forbidden"),
        context("receiver_hit", key="exfil"),
        context("output_sink_effect", key="sink"),
    ]
    collector = VerdictCollector(attacks, config())
    records = [record(attack) for attack in attacks]
    collector(records[0], evidence(records[0], calls=[call(1, "delete_account", dry_run=True)]))
    collector(records[1], evidence(records[1], hits=[hit(records[1])]))
    collector(records[2], evidence(records[2], output=envelope("<b>", sink(records[2], True))))
    verdicts = collector.finalize(run_summary(records))
    report["states"] = [result.state for result in verdicts.results]
    report["targets_imported"] = [
        name for name in ("agent_target", "verdict_target") if name in sys.modules
    ]
    report["exports"] = sorted(gazua.__all__)
    return 0


def run_target(mode: str, arguments: list[str]) -> int:
    if mode == "control":
        attempt_forbidden_actions()
        return 0
    if mode == "import":
        __import__("gazua")
        __import__("gazua.cli")
        return 0
    if mode == "wrap":
        return run_wrapped_tools(arguments)
    if mode == "verdict":
        return run_verdicts()
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
