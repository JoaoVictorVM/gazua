"""The Node runner of one attempt, started and spoken to from inside the supervised worker.

The command is fixed: the ``node`` the system resolves, the launcher shipped in this package
and the project folder, as an argument vector without a shell. Node is a descendant of the
worker, so the supervisor's timeout and tree kill end it too. Stdout carries protocol lines
only; stderr is drained and discarded. Nothing the runner prints reaches a report.
"""

from __future__ import annotations

import contextlib
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import IO, Final, TypeVar

from pydantic import BaseModel

from gazua.typescript.models import (
    MAX_LINE_BYTES,
    PROTOCOL_VERSION,
    ProtocolViolation,
    RunnerClose,
    RunnerClosed,
    RunnerError,
    decode,
    encode,
)

LAUNCHER: Final = Path(__file__).with_name("launcher.mjs")
CLOSE_SECONDS: Final = 2.0
EXIT_PACKAGE_MISSING: Final = 78
_EOF: Final = object()
_TOO_LONG: Final = object()
_Expected = TypeVar("_Expected", bound=BaseModel)


class RunnerFailed(Exception):
    """The runner could not answer. ``code`` is normalized; nothing of the target is kept."""

    def __init__(
        self, code: str, error_type: str | None = None, retry_after: float | None = None
    ) -> None:
        self.code = code
        self.error_type = error_type
        self.retry_after = retry_after
        super().__init__(code)


def runner_command(node: str, project_root: Path) -> list[str]:
    return [node, str(LAUNCHER), str(project_root)]


def _drain(stream: IO[bytes]) -> None:
    with contextlib.suppress(OSError, ValueError):
        while stream.read(65536):
            pass


class RunnerProcess:
    """One runner. Exactly one request is pending at a time, and every response matches it."""

    def __init__(self, node: str, project_root: Path, session: Path) -> None:
        self.node = node
        self.project_root = project_root
        self.session = session
        self._process: subprocess.Popen[bytes] | None = None
        self._lines: queue.Queue[object] = queue.Queue()
        self._next_id = 0
        self._broken = False

    def start(self) -> None:
        from gazua.integration.session import SESSION_ENV

        env = dict(os.environ)
        env[SESSION_ENV] = str(self.session)
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        try:
            self._process = subprocess.Popen(  # noqa: S603
                runner_command(self.node, self.project_root),
                cwd=self.project_root,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                creationflags=flags,
            )
        except OSError:
            raise RunnerFailed("typescript_node_missing") from None
        stdout, stderr = self._process.stdout, self._process.stderr
        if stdout is None or stderr is None:
            raise RunnerFailed("typescript_runner_exited")
        threading.Thread(target=self._read, args=(stdout,), daemon=True).start()
        threading.Thread(target=_drain, args=(stderr,), daemon=True).start()

    def _read(self, stream: IO[bytes]) -> None:
        try:
            while True:
                line = stream.readline(MAX_LINE_BYTES + 1)
                if not line:
                    break
                if not line.endswith(b"\n"):
                    # A line over the limit, or a partial line cut by the runner's exit.
                    self._lines.put(_TOO_LONG if len(line) > MAX_LINE_BYTES else _EOF)
                    return
                self._lines.put(line[:-1])
        except (OSError, ValueError):
            pass
        self._lines.put(_EOF)

    def _exit_failure(self) -> RunnerFailed:
        process = self._process
        code = None if process is None else process.poll()
        if code is None and process is not None:
            with contextlib.suppress(subprocess.TimeoutExpired):
                code = process.wait(CLOSE_SECONDS)
        if code == EXIT_PACKAGE_MISSING:
            return RunnerFailed("typescript_package_missing")
        return RunnerFailed("typescript_runner_exited")

    def request(
        self,
        message: BaseModel,
        expected: type[_Expected],
        *,
        deadline: float | None = None,
    ) -> _Expected | RunnerError:
        """Sends one request and returns its response: ``expected`` or a normalized error."""
        if self._broken or self._process is None or self._process.stdin is None:
            raise RunnerFailed("typescript_protocol_error")
        self._next_id += 1
        request_id = str(self._next_id)
        line = encode(message.model_copy(update={"request_id": request_id}))
        try:
            self._process.stdin.write(line)
            self._process.stdin.flush()
        except (OSError, ValueError):
            self._broken = True
            raise self._exit_failure() from None
        remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
        try:
            item = self._lines.get(timeout=remaining)
        except queue.Empty:
            self._broken = True
            raise RunnerFailed("typescript_runner_timeout") from None
        if item is _EOF:
            self._broken = True
            raise self._exit_failure()
        if item is _TOO_LONG or not isinstance(item, bytes):
            self._broken = True
            raise RunnerFailed("typescript_protocol_error")
        try:
            response = decode("to_python", item)
        except ProtocolViolation:
            self._broken = True
            raise RunnerFailed("typescript_protocol_error") from None
        if getattr(response, "request_id", None) != request_id:
            self._broken = True
            raise RunnerFailed("typescript_protocol_error")
        if isinstance(response, RunnerError | expected):
            return response
        self._broken = True
        raise RunnerFailed("typescript_protocol_error")

    def close(self) -> None:
        """Asks for a clean exit, then ends the process whatever it answered."""
        process = self._process
        if process is None:
            return
        if not self._broken and process.poll() is None:
            with contextlib.suppress(RunnerFailed, ProtocolViolation):
                self.request(
                    RunnerClose(protocol_version=PROTOCOL_VERSION, type="close", request_id="1"),
                    RunnerClosed,
                    deadline=time.monotonic() + CLOSE_SECONDS,
                )
        with contextlib.suppress(OSError):
            if process.stdin is not None:
                process.stdin.close()
        try:
            process.wait(CLOSE_SECONDS)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(OSError):
                process.kill()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(CLOSE_SECONDS)
        self._process = None

    def __enter__(self) -> RunnerProcess:
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


__all__ = ["LAUNCHER", "RunnerFailed", "RunnerProcess", "runner_command"]
