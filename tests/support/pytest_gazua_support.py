"""A tools project inside a pytester folder, for the pytest-gazua tests."""

from __future__ import annotations

import copy
import json
import shutil
from typing import Any

import pytest

from conftest import ROOT, TOOLS_CONFIG


def tools_project(pytester: pytest.Pytester, **overrides: Any) -> None:
    shutil.copy(ROOT / "tests" / "support" / "tools_target.py", pytester.path / "tools_target.py")
    document = copy.deepcopy(TOOLS_CONFIG)
    document.update(overrides)
    (pytester.path / "gazua.yaml").write_text(json.dumps(document, indent=2), encoding="utf-8")
    (pytester.path / ".gitignore").write_text(".gazua/\n", encoding="utf-8")
    pytester.makepyfile(test_regular="def test_regular():\n    assert True\n")


def outcomes(result: pytest.RunResult) -> dict[str, int]:
    return {key: value for key, value in result.parseoutcomes().items() if value}
