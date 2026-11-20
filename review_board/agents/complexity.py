"""Complexity reviewer: cyclomatic complexity, nesting, length and arity of changed functions."""

from __future__ import annotations

import ast

from ..models import ChangedFile, Finding, Severity
from .common import FuncNode, parse, touched_functions

NAME = "complexity"
NESTING = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try, ast.Match)


def cyclomatic(fn: FuncNode) -> int:
    """McCabe complexity: 1 + decision points, not counting nested function definitions."""
    score = 1

    def walk(node: ast.AST) -> None:
        nonlocal score
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                continue
            if isinstance(child, (ast.If, ast.IfExp, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.Assert)):
                score += 1
            elif isinstance(child, ast.BoolOp):
                score += len(child.values) - 1
            elif isinstance(child, ast.comprehension):
                score += 1 + len(child.ifs)
            elif isinstance(child, ast.match_case):
                score += 1
            walk(child)

    walk(fn)
    return score


def max_nesting(fn: FuncNode) -> int:
    def depth(node: ast.AST, d: int) -> int:
        best = d
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            best = max(best, depth(child, d + 1 if isinstance(child, NESTING) else d))
        return best

    return depth(fn, 0)


def run(files: list[ChangedFile]) -> tuple[list[Finding], str]:
    findings: list[Finding] = []
    worst = None
    for cf in files:
        tree = parse(cf)
        if tree is None:
            continue
        for tf in touched_functions(cf, tree):
            fn = tf.node
            cc = cyclomatic(fn)
            if worst is None or cc > worst[0]:
                worst = (cc, f"{cf.path}:{tf.qualname}")
            if cc > 10:
                sev = Severity.HIGH if cc > 20 else Severity.MEDIUM
                findings.append(Finding(NAME, "cyclomatic-complexity", sev, cf.path, fn.lineno,
                                        f"`{tf.qualname}` has cyclomatic complexity {cc} (limit 10)",
                                        "Split it into smaller functions or replace branching with a lookup table."))
            nest = max_nesting(fn)
            if nest > 4:
                findings.append(Finding(NAME, "deep-nesting", Severity.MEDIUM, cf.path, fn.lineno,
                                        f"`{tf.qualname}` nests control flow {nest} levels deep (limit 4)",
                                        "Use guard clauses / early returns to flatten it."))
            length = tf.end - fn.lineno + 1
            if length > 60:
                findings.append(Finding(NAME, "long-function", Severity.LOW, cf.path, fn.lineno,
                                        f"`{tf.qualname}` is {length} lines long (limit 60)", "Extract cohesive steps into helpers.", 0.8))
            args = fn.args
            arity = len(args.posonlyargs) + len(args.args) + len(args.kwonlyargs) - (1 if args.args and args.args[0].arg in ("self", "cls") else 0)
            if arity > 6:
                findings.append(Finding(NAME, "too-many-parameters", Severity.LOW, cf.path, fn.lineno,
                                        f"`{tf.qualname}` takes {arity} parameters (limit 6)", "Group related parameters into a dataclass.", 0.8))
    note = f"Most complex changed function: {worst[1]} (complexity {worst[0]})." if worst else "No changed Python functions."
    return findings, note
