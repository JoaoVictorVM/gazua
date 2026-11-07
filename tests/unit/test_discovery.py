import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from gazua.discovery import DiscoveryResult, discover_tools


def write(root: Path, relative: str, source: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    return path


def names(result: DiscoveryResult) -> list[str]:
    return [tool.name for tool in result.tools]


@pytest.mark.parametrize(
    "source",
    [
        """
        import gazua
        def get_order(): ...
        def send_email(): ...
        tools = gazua.wrap([get_order, send_email])
        """,
        """
        import gazua as g
        def get_order(): ...
        def send_email(): ...
        tools = g.wrap((send_email, get_order))
        """,
        """
        from gazua import wrap as w
        def get_order(): ...
        def send_email(): ...
        tools = w([get_order, send_email])
        """,
        """
        from gazua import wrap
        def get_order(): ...
        def send_email(): ...
        declared = [get_order, send_email]
        tools = wrap(declared)
        """,
        """
        from gazua import wrap
        from shop.tools import get_order, mail as send_email
        tools = wrap([get_order, send_email])
        """,
        """
        import gazua
        @gazua.tool
        def get_order(): ...
        @gazua.tool()
        async def send_email(): ...
        """,
        """
        from gazua import tool as t
        @t
        def get_order(): ...
        @t()
        async def send_email(): ...
        """,
        """
        from gazua import tool
        @tool
        def get_order(): ...
        @tool
        def send_email(): ...
        """,
    ],
    ids=[
        "wrap",
        "module-alias",
        "wrap-alias",
        "assigned-list",
        "imported",
        "decorators",
        "decorator-alias",
        "from-import",
    ],
)
def test_wrap_and_decorator_syntax_discovery(tmp_path: Path, source: str) -> None:
    write(tmp_path, "agent.py", source)

    result = discover_tools(tmp_path)
    if "mail as send_email" in source:
        assert names(result) == ["get_order", "mail"]
        return

    assert names(result) == ["get_order", "send_email"]
    assert result.complete
    assert all(tool.file == "agent.py" and tool.line > 0 for tool in result.tools)


def test_order_is_stable_across_files(tmp_path: Path) -> None:
    write(tmp_path, "z.py", "import gazua\n@gazua.tool\ndef alpha(): ...\n")
    write(tmp_path, "a/b.py", "import gazua\n@gazua.tool\ndef zeta(): ...\n")

    first = discover_tools(tmp_path)

    assert names(first) == ["alpha", "zeta"]
    assert first == discover_tools(tmp_path)


def test_keyword_argument_of_wrap_is_read(tmp_path: Path) -> None:
    write(tmp_path, "agent.py", "import gazua\ndef a(): ...\ngazua.wrap(tools=[a])\n")

    assert names(discover_tools(tmp_path)) == ["a"]


def test_module_without_gazua_is_ignored(tmp_path: Path) -> None:
    write(
        tmp_path,
        "other.py",
        """
        import other as gazua_like
        def wrap(items): ...
        def tool(f): return f
        def a(): ...
        wrap([a])
        @tool
        def b(): ...
        """,
    )

    result = discover_tools(tmp_path)

    assert result.tools == ()
    assert result.complete


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("import gazua\ndef a(): ...\ngazua.wrap(build())\n", []),
        ("import gazua\ndef a(): ...\ngazua.wrap([a, make()])\n", ["a"]),
        ("import gazua\ndef a(): ...\ngazua.wrap([*others, a])\n", ["a"]),
        ("import gazua, shop\ngazua.wrap([shop.a])\n", []),
        ("import gazua\ndef a(): ...\nt = [a]\nt = []\ngazua.wrap(t)\n", []),
        ("import gazua\ndef a(): ...\nt = [a]\nt.append(a)\ngazua.wrap(t)\n", []),
        ("import gazua\ndef a(): ...\nt = [a]\nt += [a]\ngazua.wrap(t)\n", []),
        ("import gazua\nfrom shop import *\ngazua.wrap([a])\n", []),
        ("import gazua\na = make()\ngazua.wrap([a])\n", []),
        ("import gazua\ndef f():\n    def a(): ...\n    gazua.wrap([a])\n", []),
        ("import gazua\ndef f():\n    @gazua.tool\n    def a(): ...\n", []),
        ("import gazua\nclass C:\n    @gazua.tool\n    def a(self): ...\n", []),
        ('import gazua\n@gazua.tool(name="x")\ndef a(): ...\n', []),
        ("from gazua import *\ndef a(): ...\nwrap([a])\n", []),
        ("import gazua\ndef a(): ...\ndef a(): ...\ngazua.wrap([a])\n", []),
    ],
    ids=[
        "computed-list",
        "factory-element",
        "starred",
        "attribute",
        "reassigned",
        "mutated",
        "augmented",
        "star-import",
        "factory-value",
        "closure",
        "nested-decorator",
        "method",
        "decorator-arguments",
        "star-gazua",
        "redefined",
    ],
)
def test_dynamic_and_duplicate_tools_need_review(
    tmp_path: Path, source: str, expected: list[str]
) -> None:
    write(tmp_path, "agent.py", source)

    result = discover_tools(tmp_path)

    assert names(result) == expected
    assert not result.complete
    assert all(item.code == "discovery_incomplete" for item in result.warnings)
    assert all(item.severity == "warning" for item in result.warnings)


def test_distinct_symbols_with_the_same_name_are_not_collapsed_silently(tmp_path: Path) -> None:
    write(tmp_path, "one.py", "import gazua\n@gazua.tool\ndef same(): ...\n")
    write(tmp_path, "two.py", "import gazua\n@gazua.tool\ndef same(): ...\n")

    result = discover_tools(tmp_path)

    assert names(result) == ["same"]
    assert not result.complete
    assert [item.field for item in result.warnings] == ["same"]


def test_one_symbol_reached_twice_is_not_a_duplicate(tmp_path: Path) -> None:
    write(tmp_path, "src/shop/tools.py", "import gazua\n@gazua.tool\ndef same(): ...\n")
    write(
        tmp_path,
        "tests/target.py",
        "import gazua\nfrom shop.tools import same\ngazua.wrap([same])\n",
    )
    write(
        tmp_path,
        "src/shop/agent.py",
        "import gazua\nfrom .tools import same\ngazua.wrap([same])\n",
    )

    result = discover_tools(tmp_path)

    assert names(result) == ["same"]
    assert result.complete


def test_syntax_error_reports_location_and_keeps_other_results(tmp_path: Path) -> None:
    write(tmp_path, "bad.py", "secret_literal = 'sentinel-private-value'\ndef broken(:\n")
    write(tmp_path, "good.py", "import gazua\n@gazua.tool\ndef ok(): ...\n")

    result = discover_tools(tmp_path)

    assert names(result) == ["ok"]
    assert not result.complete
    warning = result.warnings[0]
    assert (warning.file, warning.line) == ("bad.py", 2)
    assert "sentinel-private-value" not in warning.render()


def test_parsing_does_not_print_source_lines(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    write(tmp_path, "agent.py", "value = 'sentinel-private-value \\d'\n")

    discover_tools(tmp_path)

    captured = capfd.readouterr()
    assert "sentinel-private-value" not in captured.out + captured.err


def test_discovery_never_imports_or_calls_target(tmp_path: Path) -> None:
    marker = tmp_path / "executed.txt"
    probe = f"import pathlib\npathlib.Path({str(marker)!r}).write_text('x')\n"
    write(
        tmp_path,
        "agent.py",
        probe + "import gazua\ndef a(): ...\ngazua.wrap([a, pathlib.Path('z').touch()])\n",
    )

    # Positive control: the same source does have the effect when it really runs.
    exec(  # noqa: S102
        compile(probe, "probe", "exec"), {}
    )
    assert marker.exists()
    marker.unlink()

    result = discover_tools(tmp_path)

    assert names(result) == ["a"]
    assert not marker.exists()
    assert not (tmp_path / "z").exists()
    assert not list(tmp_path.rglob("__pycache__"))


@pytest.mark.parametrize(
    "directory",
    [
        ".git",
        ".gazua",
        ".venv",
        "venv",
        "node_modules",
        "build",
        "dist",
        "__pycache__",
        ".pytest_cache",
        ".agents",
        ".claude",
        ".codex",
        ".harness",
        ".planning",
        "shop.egg-info",
    ],
)
def test_discovery_skips_private_directories(tmp_path: Path, directory: str) -> None:
    write(tmp_path, f"{directory}/agent.py", "import gazua\n@gazua.tool\ndef hidden(): ...\n")
    write(tmp_path, "agent.py", "import gazua\n@gazua.tool\ndef visible(): ...\n")

    assert names(discover_tools(tmp_path)) == ["visible"]


def test_discovery_skips_symlinks_and_private_directories(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    write(outside, "linked.py", "import gazua\n@gazua.tool\ndef linked(): ...\n")
    root = tmp_path / "project"
    write(root, "agent.py", "import gazua\n@gazua.tool\ndef visible(): ...\n")
    try:
        os.symlink(outside / "linked.py", root / "file_link.py")
        os.symlink(outside, root / "dir_link", target_is_directory=True)
    except OSError:
        pytest.skip("this system does not allow creating symlinks")

    assert names(discover_tools(root)) == ["visible"]


@pytest.mark.skipif(sys.platform != "win32", reason="directory junctions exist on Windows")
def test_discovery_skips_windows_junctions(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    write(outside, "linked.py", "import gazua\n@gazua.tool\ndef linked(): ...\n")
    root = tmp_path / "project"
    write(root, "agent.py", "import gazua\n@gazua.tool\ndef visible(): ...\n")
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(root / "junction"), str(outside)],
        capture_output=True,
        check=False,
    )
    assert created.returncode == 0, created.stderr
    assert (root / "junction" / "linked.py").exists()

    assert names(discover_tools(root)) == ["visible"]


def test_only_python_files_are_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write(tmp_path, ".env", "OPENAI_API_KEY=sentinel\n")
    write(tmp_path, "notes.txt", "text\n")
    write(tmp_path, "agent.py", "x = 1\n")
    read: list[str] = []
    original = Path.read_bytes

    def spy(self: Path) -> bytes:
        read.append(self.name)
        return original(self)

    monkeypatch.setattr(Path, "read_bytes", spy)

    discover_tools(tmp_path)

    assert read == ["agent.py"]


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        (["tests/gazua_target.py"], "tests.gazua_target:entrypoint"),
        (["target.py"], "target:entrypoint"),
        (["src/shop/agent.py"], "shop.agent:entrypoint"),
        (["shop/__init__.py"], "shop:entrypoint"),
        (["one.py", "two.py"], None),
        (["not-a-module/target.py"], None),
        ([], None),
    ],
)
def test_entrypoint_is_suggested_only_when_unambiguous(
    tmp_path: Path, files: list[str], expected: str | None
) -> None:
    for file in files:
        write(tmp_path, file, "def entrypoint(message): ...\n")
    write(tmp_path, "lib.py", "def helper():\n    def entrypoint(): ...\n")

    assert discover_tools(tmp_path).entrypoint == expected
