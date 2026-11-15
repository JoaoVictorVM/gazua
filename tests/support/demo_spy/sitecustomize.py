"""Loaded by every Python process of a spied demo, the supervisor and each worker alike.

With ``GAZUA_DEMO_SPY`` set, each process appends to ``<dir>/<pid>.jsonl`` a start line, every
network audit event with its address, and every read of an environment variable shaped like a
credential, with the module that read it. Writing happens at each event, so a worker that is
killed still leaves what it did.
"""

import json
import os
import sys

_FOLDER = os.environ.get("GAZUA_DEMO_SPY")
_SUFFIXES = ("_API_KEY", "_TOKEN", "_SECRET", "_PASSWORD")
_NAMES = {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GOOGLE_APPLICATION_CREDENTIALS"}


def _write(kind, **data):
    path = os.path.join(_FOLDER, f"{os.getpid()}.jsonl")
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"kind": kind, "pid": os.getpid(), **data}, default=repr) + "\n")


def _caller():
    frame = sys._getframe(2)
    while frame is not None:
        name = frame.f_globals.get("__name__", "")
        if name not in ("os", "_collections_abc", "collections.abc", "sitecustomize"):
            return str(name)
        frame = frame.f_back
    return ""


def _audit(event, args):
    if not event.startswith(("socket.", "http.", "urllib.", "ftplib.", "smtplib.")):
        return
    address = None
    if event == "socket.connect" and len(args) > 1:
        address = args[1]
    elif event == "socket.getaddrinfo" and args:
        address = args[0]
    elif event in ("socket.sendto", "socket.bind") and len(args) > 1:
        address = args[1]
    _write("network", event=event, address=repr(address))


if _FOLDER:

    class _Spied(type(os.environ)):
        def __getitem__(self, key):
            upper = key.upper() if isinstance(key, str) else ""
            if upper.endswith(_SUFFIXES) or upper in _NAMES:
                _write("credential_read", name=key, caller=_caller())
            return super().__getitem__(key)

    _write("process")
    os.environ.__class__ = _Spied
    sys.addaudithook(_audit)
