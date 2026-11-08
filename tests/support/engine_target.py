"""A synthetic agent for run engine tests. Every behavior is chosen by the message it receives.

Markers are appended to ``marks/<pid>.jsonl`` in the working directory, so tests can see what
ran, in which process and when, after each worker is gone. One file per process, because
concurrent appends to a shared file interleave on Windows.
"""

import contextlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import gazua

MARKS = Path("marks")


def mark(kind: str, **data: object) -> None:
    line = json.dumps({"kind": kind, "pid": os.getpid(), "t": time.time(), **data})
    MARKS.mkdir(exist_ok=True)
    with (MARKS / f"{os.getpid()}.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def write_record(record_id: str) -> str:
    mark("tool_effect", id=record_id)
    return "written"


def send_email(to: str) -> str:
    mark("email_effect", to=to)
    return "sent"


TOOLS = gazua.wrap({"write_record": write_record, "send_email": send_email})

DESCENDANT = (
    "import sys, time\nwhile True:\n    open(sys.argv[1], 'a').write('x')\n    time.sleep(0.05)\n"
)


def entrypoint(message: str) -> str:
    command, _, argument = message.partition(" ")
    mark("entry_start", command=command)
    if command == "echo":
        result = "echo " + argument
    elif command == "sleep":
        time.sleep(3600)
        result = "late"
    elif command == "crash":
        os._exit(3)
    elif command == "loop":
        count = 0
        while True:
            with contextlib.suppress(gazua.GazuaBlockedError):
                TOOLS["write_record"](f"GAZUA-{count}")
            count += 1
    elif command == "429":
        raise gazua.GazuaRateLimited(retry_after=float(argument or 0))
    elif command == "dirty429":
        TOOLS["write_record"]("GAZUA-dirty")
        raise gazua.GazuaRateLimited(retry_after=0)
    elif command == "exfil":
        gazua.send_to_receiver("https://receiver.gazua.test/collect", body=argument)
        result = "sent"
    elif command == "usage":
        gazua.report_usage(cost_usd=float(argument))
        result = "used"
    elif command == "hold":
        time.sleep(float(argument))
        result = "held"
    elif command == "leak":
        print("stdout " + argument)
        print("stderr " + argument, file=sys.stderr)
        raise RuntimeError("failure carrying " + argument)
    elif command == "spawn":
        subprocess.Popen([sys.executable, "-c", DESCENDANT, argument])
        time.sleep(3600)
        result = "late"
    else:
        result = "unknown"
    mark("entry_end", command=command)
    return result


def reset() -> None:
    mark("reset")
    if Path("reset_fail").exists():
        raise RuntimeError("reset broke with private detail")
    if Path("reset_hang").exists():
        time.sleep(3600)
