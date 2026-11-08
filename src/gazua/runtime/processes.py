"""Launches one worker process and kills its whole process tree when asked.

On POSIX the worker leads its own process group and the group is killed. On Windows the
worker is placed in a Job Object that kills every member when it closes. The worker waits for
a release line on stdin, sent only after the tree is under supervision, so nothing from the
target runs before that. When supervision cannot be set up, the worker never gets released.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO

MAX_CAPTURE_BYTES = 64 * 1024
RELEASE_LINE = b"go\n"
_CHUNK = 8192
_DRAIN_JOIN_SECONDS = 2.0
_REAP_SECONDS = 10.0


class SupervisionError(Exception):
    """The worker's process tree could not be put under supervision."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class Capture:
    """At most ``MAX_CAPTURE_BYTES`` of one stream. ``truncated`` says more was discarded."""

    data: bytes
    truncated: bool


class _Drain(threading.Thread):
    """Reads a pipe to its end so the worker never blocks on a full pipe."""

    def __init__(self, stream: IO[bytes]) -> None:
        super().__init__(daemon=True)
        self._stream = stream
        self._kept = bytearray()
        self._truncated = False

    def run(self) -> None:
        with contextlib.suppress(OSError, ValueError):
            descriptor = self._stream.fileno()
            while chunk := os.read(descriptor, _CHUNK):
                room = MAX_CAPTURE_BYTES - len(self._kept)
                if room > 0:
                    self._kept.extend(chunk[:room])
                if len(chunk) > room:
                    self._truncated = True

    def capture(self) -> Capture:
        return Capture(bytes(self._kept), self._truncated)


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
    _PROCESS_SET_QUOTA = 0x0100
    _PROCESS_TERMINATE = 0x0001
    _CREATE_NO_WINDOW = 0x08000000

    class _BasicLimits(ctypes.Structure):
        _fields_ = (
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        )

    class _IoCounters(ctypes.Structure):
        _fields_ = tuple((name, ctypes.c_uint64) for name in ("r", "w", "o", "rb", "wb", "ob"))

    class _ExtendedLimits(ctypes.Structure):
        _fields_ = (
            ("BasicLimitInformation", _BasicLimits),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        )

    _kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    _kernel32.CreateJobObjectW.argtypes = (wintypes.LPVOID, wintypes.LPCWSTR)
    _kernel32.SetInformationJobObject.restype = wintypes.BOOL
    _kernel32.SetInformationJobObject.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    _kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    _kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    _kernel32.TerminateJobObject.restype = wintypes.BOOL
    _kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)

    class _Tree:
        """A Job Object that holds the worker and every process it starts."""

        def __init__(self, pid: int) -> None:
            job = _kernel32.CreateJobObjectW(None, None)
            if not job:
                raise SupervisionError("job_object_unavailable")
            self._job: int | None = job
            info = _ExtendedLimits()
            info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            process = None
            try:
                if not _kernel32.SetInformationJobObject(
                    job,
                    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
                    ctypes.byref(info),
                    ctypes.sizeof(info),
                ):
                    raise SupervisionError("job_object_unavailable")
                process = _kernel32.OpenProcess(_PROCESS_SET_QUOTA | _PROCESS_TERMINATE, False, pid)
                if not process or not _kernel32.AssignProcessToJobObject(job, process):
                    raise SupervisionError("job_assignment_failed")
            except SupervisionError:
                self.close()
                raise
            finally:
                if process:
                    _kernel32.CloseHandle(process)

        def kill(self) -> bool:
            return self._job is None or bool(_kernel32.TerminateJobObject(self._job, 1))

        def close(self) -> None:
            if self._job is not None:
                _kernel32.CloseHandle(self._job)
                self._job = None

    def _popen_options() -> dict[str, object]:
        return {"creationflags": _CREATE_NO_WINDOW}

else:
    import signal

    class _Tree:
        """The worker's own process group, created with a new session at launch."""

        def __init__(self, pid: int) -> None:
            try:
                group = os.getpgid(pid)
            except OSError:
                raise SupervisionError("process_group_unavailable") from None
            if group != pid:
                raise SupervisionError("process_group_unavailable")
            self._group = group

        def kill(self) -> bool:
            try:
                os.killpg(self._group, signal.SIGKILL)
            except ProcessLookupError:
                return True
            except OSError:
                return False
            return True

        def close(self) -> None:
            self.kill()

    def _popen_options() -> dict[str, object]:
        return {"start_new_session": True}


class SupervisedProcess:
    """One worker. ``start`` only returns after the whole tree is supervised and released."""

    def __init__(self, argv: Sequence[str], cwd: Path) -> None:
        self._argv = [str(part) for part in argv]
        self._cwd = cwd
        self._process: subprocess.Popen[bytes] | None = None
        self._tree: _Tree | None = None
        self._drains: tuple[_Drain, _Drain] | None = None
        self.kill_failed = False

    @property
    def pid(self) -> int | None:
        return None if self._process is None else self._process.pid

    def start(self) -> None:
        # The argument list is built by Gazua from the running interpreter, never by a shell.
        process = subprocess.Popen(  # noqa: S603
            self._argv,
            cwd=self._cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **_popen_options(),  # type: ignore[arg-type]
        )
        self._process = process
        stdout, stderr = process.stdout, process.stderr
        if stdout is None or stderr is None:
            raise SupervisionError("pipes_unavailable")
        self._drains = (_Drain(stdout), _Drain(stderr))
        for drain in self._drains:
            drain.start()
        try:
            self._tree = _Tree(process.pid)
        except SupervisionError:
            process.kill()
            self._finish_reaping()
            raise
        try:
            assert process.stdin is not None  # noqa: S101
            process.stdin.write(RELEASE_LINE)
            process.stdin.close()
        except OSError:
            # The worker already exited; poll() reports how.
            pass

    def poll(self) -> int | None:
        return None if self._process is None else self._process.poll()

    def wait(self, timeout: float) -> int | None:
        if self._process is None:
            return None
        try:
            return self._process.wait(timeout)
        except subprocess.TimeoutExpired:
            return None

    def kill_tree(self) -> bool:
        """Kills the worker and its descendants and reaps the worker. False when it failed."""
        if self._process is None:
            return True
        killed = self._tree.kill() if self._tree is not None else False
        if not killed:
            with contextlib.suppress(OSError):
                self._process.kill()
        reaped = self.wait(_REAP_SECONDS) is not None
        if not (killed and reaped):
            self.kill_failed = True
        return killed and reaped

    def close(self) -> tuple[Capture, Capture]:
        """Ends anything the worker left behind and returns what it printed."""
        if self._tree is not None:
            self._tree.kill()
            self._tree.close()
            self._tree = None
        self._finish_reaping()
        if self._drains is None:
            return Capture(b"", False), Capture(b"", False)
        for drain in self._drains:
            drain.join(_DRAIN_JOIN_SECONDS)
        stdout, stderr = (drain.capture() for drain in self._drains)
        return stdout, stderr

    def _finish_reaping(self) -> None:
        if self._process is not None and self.wait(_REAP_SECONDS) is None:
            self.kill_failed = True


def worker_command(*arguments: str) -> list[str]:
    """The worker command line for the interpreter running Gazua, without any shell."""
    return [sys.executable, "-m", "gazua.runtime.worker", *arguments]
