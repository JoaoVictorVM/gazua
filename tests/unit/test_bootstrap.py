import re
import subprocess
from pathlib import Path

import pytest

from gazua import _bootstrap, cli

PROBE = """
import sys
sys.path.insert(0, sys.argv[1])
from gazua._bootstrap import main
code = main()
assert not {"typer", "gazua.cli"} & set(sys.modules), "dependencies were imported"
sys.exit(code)
"""


def test_supported_python_enters_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "main", lambda: 42)
    assert _bootstrap.main() == 42


@pytest.mark.python310
def test_python_310_reports_required_version(python310: str, project_root: Path) -> None:
    result = subprocess.run(
        [python310, "-I", "-c", PROBE, str(project_root / "src")],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2, result.stderr
    assert result.stdout == ""
    assert re.fullmatch(
        r"Gazua requires Python 3\.11 or newer; found 3\.10\.\d+\.\n", result.stderr
    )
