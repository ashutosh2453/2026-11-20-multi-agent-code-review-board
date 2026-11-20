"""Helpers shared by the reviewer agents."""

from __future__ import annotations

import ast
from dataclasses import dataclass

from ..models import ChangedFile

FuncNode = ast.FunctionDef | ast.AsyncFunctionDef


@dataclass
class TouchedFunction:
    node: FuncNode
    qualname: str
    start: int
    end: int
    def_line_added: bool  # the function is new (its signature line was added)


def parse(cf: ChangedFile) -> ast.Module | None:
    if not cf.is_python or cf.new_source is None:
        return None
    try:
        return ast.parse(cf.new_source)
    except SyntaxError:
        return None


def touched_functions(cf: ChangedFile, tree: ast.Module) -> list[TouchedFunction]:
    """Functions/methods whose body intersects the added lines (innermost wins)."""
    out: list[TouchedFunction] = []
    added = set(cf.added_lines)

    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = f"{prefix}{child.name}"
                if isinstance(child, ast.ClassDef):
                    visit(child, name + ".")
                    continue
                start = min([child.lineno] + [d.lineno for d in child.decorator_list])
                end = child.end_lineno or child.lineno
                if any(start <= ln <= end for ln in added):
                    out.append(TouchedFunction(child, name, start, end, child.lineno in added))
                visit(child, name + ".")
            else:
                visit(child, prefix)

    visit(tree, "")
    return out


def call_name(node: ast.Call) -> str:
    """Dotted name of the called function, e.g. 'subprocess.run' or 'eval'."""
    parts = []
    f = node.func
    while isinstance(f, ast.Attribute):
        parts.append(f.attr)
        f = f.value
    if isinstance(f, ast.Name):
        parts.append(f.id)
    return ".".join(reversed(parts))


def kwarg(node: ast.Call, name: str) -> ast.expr | None:
    return next((k.value for k in node.keywords if k.arg == name), None)


def is_true(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def is_false(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False
