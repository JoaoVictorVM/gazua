import sys
import time
from pathlib import Path

from gazua.runtime.processes import MAX_CAPTURE_BYTES, SupervisedProcess

SCRIPT = r"""
import subprocess, sys, time
if sys.stdin.buffer.readline() != b"go\n":
    sys.exit(9)
mode, marker = sys.argv[1], sys.argv[2]
WRITER = (
    "import sys, time\n"
    "while True:\n"
    "    with open(sys.argv[1], 'a') as handle: handle.write('x')\n"
    "    time.sleep(0.05)\n"
)
if mode == "tree":
    subprocess.Popen([sys.executable, "-c", WRITER, marker])
    time.sleep(3600)
if mode == "flood":
    for _ in range(64):
        sys.stdout.buffer.write(b"o" * 65536)
        sys.stderr.buffer.write(b"e" * 65536)
    sys.stdout.flush()
    sys.stderr.flush()
    open(marker, "w").write("done")
"""


def launch(tmp_path: Path, mode: str) -> tuple[SupervisedProcess, Path]:
    script = tmp_path / "child.py"
    script.write_text(SCRIPT, encoding="utf-8")
    marker = tmp_path / "marker.txt"
    process = SupervisedProcess([sys.executable, str(script), mode, str(marker)], tmp_path)
    process.start()
    return process, marker


def size(path: Path) -> int:
    return path.stat().st_size if path.exists() else 0


def test_timeout_kills_worker_descendants_on_supported_platforms(tmp_path: Path) -> None:
    process, marker = launch(tmp_path, "tree")
    deadline = time.monotonic() + 20
    while size(marker) < 3 and time.monotonic() < deadline:
        time.sleep(0.05)
    assert size(marker) >= 3, "the descendant never started writing"
    assert process.poll() is None

    assert process.kill_tree() is True
    process.close()
    time.sleep(0.3)
    stopped_at = size(marker)
    time.sleep(0.6)

    assert size(marker) == stopped_at
    assert process.poll() is not None
    assert process.kill_failed is False


def test_output_flood_does_not_deadlock_or_escape_capture_limits(tmp_path: Path) -> None:
    process, marker = launch(tmp_path, "flood")

    exit_code = process.wait(60)
    stdout, stderr = process.close()

    assert exit_code == 0
    assert marker.read_text(encoding="utf-8") == "done"
    assert len(stdout.data) == MAX_CAPTURE_BYTES
    assert len(stderr.data) == MAX_CAPTURE_BYTES
    assert stdout.truncated
    assert stderr.truncated
    assert set(stdout.data) == {ord("o")}


def test_worker_does_nothing_before_release(tmp_path: Path) -> None:
    script = tmp_path / "gate.py"
    script.write_text(
        "import sys\nopen(sys.argv[1], 'w').write(repr(sys.stdin.buffer.readline()))\n",
        encoding="utf-8",
    )
    marker = tmp_path / "gate.txt"
    process = SupervisedProcess([sys.executable, str(script), str(marker)], tmp_path)
    process.start()

    assert process.wait(30) == 0
    process.close()
    assert marker.read_text(encoding="utf-8") == "b'go\\n'"
