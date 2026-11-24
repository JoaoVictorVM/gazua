import os
from pathlib import Path

import pytest

from gazua.diagnostics import ConfigError
from gazua.typescript.policy import check_module, module_path_problem, module_sha256


def code(root: Path, module: str) -> str:
    with pytest.raises(ConfigError) as caught:
        check_module(root, module)
    return caught.value.diagnostics[0].code


def test_module_stays_regular_and_inside_project(tmp_path: Path) -> None:
    root = tmp_path / "project"
    (root / "dist").mkdir(parents=True)
    module = root / "dist" / "agent.js"
    module.write_text("export const respond = () => 'ok';\n", encoding="utf-8")
    (root / "dist" / "folder.js").mkdir()
    outside = tmp_path / "outside.js"
    outside.write_text("export {};\n", encoding="utf-8")

    assert check_module(root, "dist/agent.js") == root / "dist" / "agent.js"
    assert check_module(root, "./dist/agent.js").name == "agent.js"
    for text in (
        "../outside.js",
        "dist/../../outside.js",
        "/etc/agent.js",
        "file:///agent.js",
        "https://example.test/a.js",
        "dist/agent.ts",
        "gazua",
        "dist\\agent.js",
        "dist/agent.js#fragment",
        "dist/agent.js?query",
    ):
        assert module_path_problem(text) is not None, text
        assert code(root, text) == "typescript_module_invalid", text
    assert code(root, "dist/missing.js") == "typescript_module_missing"
    assert code(root, "dist/folder.js") == "typescript_module_invalid"

    # The hash covers the bytes Node loads, so any change of the compiled module shows.
    first = module_sha256(module)
    module.write_text("export const respond = () => 'changed';\n", encoding="utf-8")
    assert module_sha256(module) != first

    link = root / "dist" / "linked.js"
    try:
        os.symlink(outside, link)
    except OSError:
        pytest.skip("Symbolic links are not available to this user.")
    assert code(root, "dist/linked.js") == "typescript_module_invalid"
