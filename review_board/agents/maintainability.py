"""Maintainability reviewer: error handling, debugging leftovers, mutable defaults, docs and TODOs."""

from __future__ import annotations

import ast
import re

from ..models import ChangedFile, Finding, Severity
from .common import call_name, parse, touched_functions

NAME = "maintainability"
TODO = re.compile(r"(?:#|//|/\*)\s*(TODO|FIXME|XXX|HACK)\b[:\s]*(.*)", re.I)


def review_python(cf: ChangedFile, tree: ast.Module) -> list[Finding]:
    added = set(cf.added_lines)
    main_block = _main_guard_lines(tree)
    is_script = bool(main_block) and any(isinstance(n, ast.FunctionDef) and n.name == "main" for n in tree.body)
    out: list[Finding] = []
    for node in ast.walk(tree):
        line = getattr(node, "lineno", None)
        if line not in added:
            continue
        if isinstance(node, ast.ExceptHandler):
            swallow = all(isinstance(s, (ast.Pass, ast.Continue)) or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)) for s in node.body)
            broad = node.type is None or (isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException"))
            if node.type is None:
                out.append(Finding(NAME, "bare-except", Severity.MEDIUM, cf.path, line, "Bare `except:` also catches KeyboardInterrupt and SystemExit",
                                   "Catch the specific exceptions you expect."))
            elif broad and swallow:
                out.append(Finding(NAME, "swallowed-exception", Severity.MEDIUM, cf.path, line, "Exception is caught and silently ignored",
                                   "Log it, re-raise, or narrow the exception type."))
        elif isinstance(node, ast.Call):
            name = call_name(node)
            if name in ("breakpoint", "pdb.set_trace", "ipdb.set_trace"):
                out.append(Finding(NAME, "debugger-left-in", Severity.HIGH, cf.path, line, f"Debugger call `{name}()` left in code", "Remove it."))
            elif name == "print" and not cf.is_test and not is_script and line not in main_block \
                    and not re.search(r"(cli|__main__|scripts?/|manage)\b", cf.path):
                out.append(Finding(NAME, "print-statement", Severity.LOW, cf.path, line, "`print()` in library code", "Use the logging module.", 0.6))
    for tf in touched_functions(cf, tree):
        fn = tf.node
        for d in fn.args.defaults + [d for d in fn.args.kw_defaults if d is not None]:
            if isinstance(d, (ast.List, ast.Dict, ast.Set)) or (isinstance(d, ast.Call) and call_name(d) in ("list", "dict", "set")):
                out.append(Finding(NAME, "mutable-default", Severity.MEDIUM, cf.path, fn.lineno,
                                   f"`{tf.qualname}` uses a mutable default argument, shared across calls", "Default to None and create the object inside."))
                break
        if tf.def_line_added and not tf.qualname.split(".")[-1].startswith("_") and not cf.is_test and ast.get_docstring(fn) is None and tf.end - fn.lineno >= 5:
            out.append(Finding(NAME, "missing-docstring", Severity.INFO, cf.path, fn.lineno, f"New public function `{tf.qualname}` has no docstring",
                               "Document what it does, its arguments and its return value.", 0.7))
    return out


def line_ending_churn(cf: ChangedFile) -> Finding | None:
    """Flag a modified file whose line endings flipped (LF<->CRLF): every line shows as changed."""
    added, removed = len(cf.added_lines), cf.removed_count
    if cf.status != "modified" or added < 20 or removed < 20:
        return None
    to_crlf = cf.crlf_added / added > 0.9 and cf.crlf_removed / removed < 0.1
    to_lf = cf.crlf_removed / removed > 0.9 and cf.crlf_added / added < 0.1
    if not (to_crlf or to_lf):
        return None
    direction = "LF to CRLF" if to_crlf else "CRLF to LF"
    return Finding(NAME, "line-ending-churn", Severity.MEDIUM, cf.path, None,
                   f"Line endings changed from {direction} ({removed} lines removed, {added} added): the real change is hidden",
                   "Restore the original endings (git add --renormalize .) and add a .gitattributes, e.g. `* text=auto`.", 0.95)


def _main_guard_lines(tree: ast.Module) -> set[int]:
    """Lines inside `if __name__ == "__main__":` blocks, where printing is expected."""
    lines: set[int] = set()
    for node in tree.body:
        if isinstance(node, ast.If) and "__main__" in ast.unparse(node.test) and "__name__" in ast.unparse(node.test):
            lines.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
    return lines


def run(files: list[ChangedFile]) -> tuple[list[Finding], str]:
    findings: list[Finding] = []
    todos = 0
    for cf in files:
        if cf.status == "deleted":
            continue
        churn = line_ending_churn(cf)
        if churn:
            findings.append(churn)
        for line_no, text in cf.added_lines.items():
            m = TODO.search(text)
            if m:
                todos += 1
                findings.append(Finding(NAME, "todo-added", Severity.INFO, cf.path, line_no, f"{m.group(1).upper()} added: {m.group(2).strip()[:80]}",
                                        "Track it in an issue so it isn't forgotten.", 0.9))
            if cf.path.endswith((".js", ".jsx", ".ts", ".tsx")) and re.search(r"\bconsole\.log\(", text) and not cf.is_test:
                findings.append(Finding(NAME, "console-log", Severity.LOW, cf.path, line_no, "`console.log` left in code", "Remove it or use a logger.", 0.7))
            if re.search(r"\bdebugger;", text):
                findings.append(Finding(NAME, "debugger-left-in", Severity.HIGH, cf.path, line_no, "`debugger;` statement left in code", "Remove it."))
        tree = parse(cf)
        if tree is not None:
            findings += review_python(cf, tree)
    note = f"{len(findings)} maintainability note(s), {todos} new TODO(s)." if findings else "Changed code looks clean."
    return findings, note
