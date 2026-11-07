"""Finds tools declared in Python files by reading their syntax tree.

Files are parsed, never imported or executed. What a tree cannot prove (computed lists,
reassignments, closures) becomes a warning that asks for a manual declaration, because a
missing name here says nothing about what exists at runtime.
"""

from __future__ import annotations

import ast
import os
import warnings
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Literal

from gazua.config.diagnostics import Diagnostic
from gazua.config.references import is_dotted_name

EXCLUDED_DIRECTORIES = frozenset(
    {
        ".agents",
        ".claude",
        ".codex",
        ".eggs",
        ".gazua",
        ".git",
        ".harness",
        ".hg",
        ".hypothesis",
        ".idea",
        ".mypy_cache",
        ".nox",
        ".planning",
        ".pytest_cache",
        ".ruff_cache",
        ".svn",
        ".tox",
        ".venv",
        ".vscode",
        "__pycache__",
        "build",
        "dist",
        "env",
        "node_modules",
        "site-packages",
        "venv",
    }
)
_LIST_MUTATORS = frozenset({"append", "clear", "extend", "insert", "pop", "remove", "reverse"})
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400

_DYNAMIC_MESSAGE = "This form cannot be read statically; declare its tools manually."
_NESTED_MESSAGE = "Nested tools cannot be read statically; declare them manually."


@dataclass(frozen=True, slots=True)
class DiscoveredTool:
    name: str
    file: str
    line: int
    source: Literal["wrap", "decorator"]


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    tools: tuple[DiscoveredTool, ...]
    warnings: tuple[Diagnostic, ...]
    entrypoint: str | None

    @property
    def complete(self) -> bool:
        return not self.warnings


@dataclass
class _Symbol:
    """A name found in one module. ``identity`` tells apart equal names of distinct objects."""

    tool: DiscoveredTool
    identity: str


@dataclass
class _ModuleReport:
    symbols: list[_Symbol] = field(default_factory=list[_Symbol])
    warnings: list[Diagnostic] = field(default_factory=list[Diagnostic])
    defines_entrypoint: bool = False


def _is_link(path: Path) -> bool:
    # On Windows with Python 3.11, os.walk and is_symlink do not see directory junctions.
    if path.is_symlink():
        return True
    try:
        attributes: int = getattr(os.lstat(path), "st_file_attributes", 0)
    except OSError:
        return True
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _python_files(root: Path, unreadable: list[Diagnostic]) -> list[Path]:
    def report_unreadable(error: OSError) -> None:
        where = Path(error.filename).relative_to(root).as_posix() if error.filename else "."
        message = "This directory could not be read; declare its tools manually."
        unreadable.append(_warning(where, None, "", message))

    found: list[Path] = []
    for directory, subdirectories, files in os.walk(
        root, onerror=report_unreadable, followlinks=False
    ):
        current = Path(directory)
        subdirectories[:] = sorted(
            name
            for name in subdirectories
            if name not in EXCLUDED_DIRECTORIES
            and not name.endswith(".egg-info")
            and not _is_link(current / name)
        )
        found.extend(
            current / name
            for name in sorted(files)
            if name.endswith(".py") and not _is_link(current / name)
        )
    return sorted(found, key=lambda path: path.relative_to(root).as_posix())


def _module_parts(relative: str) -> tuple[str, ...] | None:
    """Dotted module of a file relative to the root, or None when it is not importable."""
    parts = list(PurePosixPath(relative).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    if not parts or not is_dotted_name(".".join(parts)):
        return None
    return tuple(parts)


def _import_path(root: Path, relative: str) -> tuple[str, ...] | None:
    parts = _module_parts(relative)
    # A top-level src folder without __init__.py is the src layout: it is not a package.
    if parts and len(parts) > 1 and parts[0] == "src" and not (root / "src/__init__.py").exists():
        return parts[1:]
    return parts


def _warning(file: str, node: ast.AST | None, field_name: str, message: str) -> Diagnostic:
    return Diagnostic(
        code="discovery_incomplete",
        severity="warning",
        file=file,
        line=getattr(node, "lineno", None),
        column=(getattr(node, "col_offset", -1) + 1) or None,
        field=field_name,
        message=message,
    )


class _GazuaNames:
    """The names under which this module can reach ``gazua``, ``wrap`` and ``tool``."""

    def __init__(self, tree: ast.Module) -> None:
        self.modules: set[str] = set()
        self.wrap: set[str] = set()
        self.tool: set[str] = set()
        self.star_imports: list[ast.ImportFrom] = []
        self.star_from_gazua = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "gazua":
                        self.modules.add(alias.asname or "gazua")
            elif isinstance(node, ast.ImportFrom):
                self._from_import(node)

    def _from_import(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name == "*":
                self.star_imports.append(node)
                self.star_from_gazua |= node.level == 0 and node.module == "gazua"
            elif node.level == 0 and node.module == "gazua":
                if alias.name == "wrap":
                    self.wrap.add(alias.asname or "wrap")
                elif alias.name == "tool":
                    self.tool.add(alias.asname or "tool")

    @property
    def used(self) -> bool:
        return bool(self.modules or self.wrap or self.tool or self.star_from_gazua)

    def is_wrap(self, func: ast.expr) -> bool:
        return self._matches(func, "wrap", self.wrap)

    def is_tool(self, func: ast.expr) -> bool:
        return self._matches(func, "tool", self.tool)

    def _matches(self, func: ast.expr, attribute: str, aliases: set[str]) -> bool:
        if isinstance(func, ast.Name):
            return func.id in aliases
        return (
            isinstance(func, ast.Attribute)
            and func.attr == attribute
            and isinstance(func.value, ast.Name)
            and func.value.id in self.modules
        )


class _ModuleBindings(ast.NodeVisitor):
    """What each name in the module was bound to, and how many times."""

    def __init__(self) -> None:
        self.depth = 0
        self.top_functions: defaultdict[str, list[ast.AST]] = defaultdict(list)
        self.nested_functions: set[str] = set()
        self.imports: dict[str, ast.ImportFrom] = {}
        self.imported_names: dict[str, str] = {}
        self.values: defaultdict[str, list[ast.expr | None]] = defaultdict(list)

    def _scope(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> None:
        self.depth += 1
        self.generic_visit(node)
        self.depth -= 1

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        if self.depth == 0:
            self.top_functions[node.name].append(node)
        else:
            self.nested_functions.add(node.name)
        self._scope(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scope(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name != "*":
                bound = alias.asname or alias.name
                self.imports[bound] = node
                self.imported_names[bound] = alias.name

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.values[target.id].append(node.value)
            else:
                self._unpacked(target)
        self.generic_visit(node)

    def _unpacked(self, target: ast.expr) -> None:
        for inner in ast.walk(target):
            if isinstance(inner, ast.Name):
                self.values[inner.id].append(None)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and node.value is not None:
            self.values[node.target.id].append(node.value)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if isinstance(node.target, ast.Name):
            self.values[node.target.id].append(None)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self._unpacked(node.target)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr in _LIST_MUTATORS
            and isinstance(func.value, ast.Name)
        ):
            self.values[func.value.id].append(None)
        self.generic_visit(node)


class _ToolCollector(ast.NodeVisitor):
    def __init__(
        self, relative: str, names: _GazuaNames, bindings: _ModuleBindings, module: str
    ) -> None:
        self.relative = relative
        self.names = names
        self.bindings = bindings
        self.module = module
        self.depth = 0
        self.report = _ModuleReport()

    def _warn(self, node: ast.AST, field_name: str, message: str) -> None:
        self.report.warnings.append(_warning(self.relative, node, field_name, message))

    def _add(
        self, name: str, node: ast.AST, source: Literal["wrap", "decorator"], key: str
    ) -> None:
        tool = DiscoveredTool(name, self.relative, getattr(node, "lineno", 1), source)
        self.report.symbols.append(_Symbol(tool, key))

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self._decorator(decorator, node)
        self.depth += 1
        self.generic_visit(node)
        self.depth -= 1

    def _decorator(self, decorator: ast.expr, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        has_arguments = isinstance(decorator, ast.Call) and bool(
            decorator.args or decorator.keywords
        )
        if not self.names.is_tool(target):
            return
        if self.depth > 0:
            self._warn(node, node.name, _NESTED_MESSAGE)
        elif has_arguments:
            self._warn(node, node.name, _DYNAMIC_MESSAGE)
        else:
            self._add(node.name, node, "decorator", f"{self.module}:{node.name}")

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.depth += 1
        self.generic_visit(node)
        self.depth -= 1

    def visit_Call(self, node: ast.Call) -> None:
        if self.names.is_wrap(node.func):
            self._wrap_call(node)
        self.generic_visit(node)

    def _wrap_call(self, node: ast.Call) -> None:
        argument = node.args[0] if node.args else None
        if argument is None:
            argument = next((item.value for item in node.keywords if item.arg == "tools"), None)
        elements = self._elements(argument)
        if elements is None:
            self._warn(node, "gazua.wrap", _DYNAMIC_MESSAGE)
            return
        for element in elements:
            self._wrap_element(element)

    def _elements(self, argument: ast.expr | None) -> list[ast.expr] | None:
        if isinstance(argument, ast.List | ast.Tuple):
            return argument.elts
        if isinstance(argument, ast.Name):
            assigned = self.bindings.values.get(argument.id, [])
            if len(assigned) == 1 and isinstance(assigned[0], ast.List | ast.Tuple):
                return assigned[0].elts
        return None

    def _wrap_element(self, element: ast.expr) -> None:
        if not isinstance(element, ast.Name):
            self._warn(element, "gazua.wrap", _DYNAMIC_MESSAGE)
            return
        name = element.id
        bindings = self.bindings
        local = len(bindings.top_functions.get(name, []))
        rebound = name in bindings.values
        imported = name in bindings.imports
        if local + int(imported) > 1 or (rebound and (local or imported)):
            self._warn(element, name, "This name is bound more than once; review it manually.")
        elif local == 1:
            self._add(name, element, "wrap", f"{self.module}:{name}")
        elif imported:
            original = bindings.imported_names[name]
            self._add(original, element, "wrap", self._imported_identity(name, original))
        elif name in bindings.nested_functions:
            self._warn(element, name, _NESTED_MESSAGE)
        else:
            self._warn(element, name, _DYNAMIC_MESSAGE)

    def _imported_identity(self, bound: str, original: str) -> str:
        node = self.bindings.imports[bound]
        if node.level == 0:
            return f"{node.module}:{original}"
        package = self.module.split(".")
        # A package's __init__.py is already inside the package that level 1 refers to.
        levels_up = node.level - 1 if self.relative.endswith("__init__.py") else node.level
        anchor = package[: max(len(package) - levels_up, 0)]
        target = ".".join([*anchor, *([node.module] if node.module else [])])
        return f"{target}:{original}"


def _parse(path: Path, relative: str) -> ast.Module | Diagnostic:
    message = "This file could not be analyzed; declare its tools manually."
    try:
        source = path.read_bytes()
        # Parsing can print warnings that quote source lines, and literals must stay private.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return ast.parse(source)
    except SyntaxError as error:
        line, column = error.lineno, error.offset
        return Diagnostic(
            code="discovery_incomplete",
            severity="warning",
            file=relative,
            line=line,
            column=column if line is not None else None,
            message=message,
        )
    except (OSError, ValueError, RecursionError, MemoryError):
        return _warning(relative, None, "", message)


def _analyze(root: Path, path: Path) -> _ModuleReport:
    relative = path.relative_to(root).as_posix()
    parsed = _parse(path, relative)
    if isinstance(parsed, Diagnostic):
        return _ModuleReport(warnings=[parsed])
    bindings = _ModuleBindings()
    bindings.visit(parsed)
    names = _GazuaNames(parsed)
    module = ".".join(_import_path(root, relative) or (relative,))
    report = _ModuleReport()
    if names.used:
        collector = _ToolCollector(relative, names, bindings, module)
        collector.visit(parsed)
        report = collector.report
        for star in names.star_imports:
            report.warnings.append(
                _warning(relative, star, "import *", "Star imports can hide tools; review them.")
            )
    report.defines_entrypoint = "entrypoint" in bindings.top_functions
    return report


def _duplicate_warnings(symbols: list[_Symbol]) -> list[Diagnostic]:
    identities: defaultdict[str, dict[str, _Symbol]] = defaultdict(dict)
    for symbol in symbols:
        identities[symbol.tool.name].setdefault(symbol.identity, symbol)
    message = "Distinct objects share this tool name; review them manually."
    duplicates: list[Diagnostic] = []
    for name, by_identity in sorted(identities.items()):
        if len(by_identity) > 1:
            second = list(by_identity.values())[1]
            duplicates.append(_warning(second.tool.file, None, name, message))
    return duplicates


def _unique_tools(symbols: list[_Symbol]) -> tuple[DiscoveredTool, ...]:
    by_name: dict[str, DiscoveredTool] = {}
    for symbol in symbols:
        by_name.setdefault(symbol.tool.name, symbol.tool)
    return tuple(by_name[name] for name in sorted(by_name))


def _entrypoint_reference(root: Path, modules: list[str]) -> str | None:
    if len(modules) != 1:
        return None
    parts = _import_path(root, modules[0])
    return f"{'.'.join(parts)}:entrypoint" if parts else None


def discover_tools(root: Path) -> DiscoveryResult:
    """Analyzes the project's Python files in a stable order, without running any of them."""
    symbols: list[_Symbol] = []
    found_warnings: list[Diagnostic] = []
    entrypoint_files: list[str] = []
    for path in _python_files(root, found_warnings):
        report = _analyze(root, path)
        symbols.extend(report.symbols)
        found_warnings.extend(report.warnings)
        if report.defines_entrypoint:
            entrypoint_files.append(path.relative_to(root).as_posix())
    found_warnings.extend(_duplicate_warnings(symbols))
    return DiscoveryResult(
        tools=_unique_tools(symbols),
        warnings=tuple(found_warnings),
        entrypoint=_entrypoint_reference(root, entrypoint_files),
    )
