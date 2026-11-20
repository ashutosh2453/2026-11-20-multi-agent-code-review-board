"""Security reviewer: dangerous calls (AST) and leaked secrets (any language), on changed lines only."""

from __future__ import annotations

import ast
import math
import re
from collections import Counter

from ..models import ChangedFile, Finding, Severity
from .common import call_name, is_false, is_true, kwarg, parse

NAME = "security"

SECRET_PATTERNS = [
    ("aws-access-key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), Severity.CRITICAL),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), Severity.CRITICAL),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), Severity.CRITICAL),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), Severity.HIGH),
]
ASSIGNED_SECRET = re.compile(r"""(?i)\b(api[_-]?key|secret|passw(?:or)?d|token|auth)\w*\s*[:=]\s*["']([^"'\s]{8,})["']""")
PLACEHOLDER = re.compile(r"(?i)(example|changeme|change-me|dummy|placeholder|your[_-]|xxx|\*\*\*|<.*>|\$\{|os\.environ|getenv|test)")
JS_RISKS = [
    ("js-eval", re.compile(r"\beval\s*\(|new Function\s*\("), Severity.HIGH, "eval/new Function executes arbitrary code"),
    ("js-inner-html", re.compile(r"\.innerHTML\s*=\s*[^'\"\s;]|dangerouslySetInnerHTML"), Severity.MEDIUM,
     "assigning dynamic HTML enables XSS; use textContent or sanitise"),
]
SQL_KEYWORDS = re.compile(r"(?i)\b(select|insert|update|delete)\b.*\b(from|into|set|where)\b")


def entropy(s: str) -> float:
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def _f(rule, sev, cf, line, msg, fix, conf=0.9) -> Finding:
    return Finding(NAME, rule, sev, cf.path, line, msg, fix, conf)


def _is_dynamic_string(node: ast.expr) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"


def _string_text(node: ast.expr) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
    if isinstance(node, ast.BinOp):
        return _string_text(node.left) + _string_text(node.right)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return _string_text(node.func.value)
    return ""


def review_python(cf: ChangedFile, tree: ast.Module) -> list[Finding]:
    added = set(cf.added_lines)
    out: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or node.lineno not in added:
            continue
        name = call_name(node)
        last = name.rsplit(".", 1)[-1]
        if name in ("eval", "exec"):
            out.append(_f("code-injection", Severity.HIGH, cf, node.lineno, f"`{name}()` executes arbitrary code",
                          "Parse the input explicitly (e.g. ast.literal_eval, json.loads) instead."))
        elif name.startswith("subprocess.") and is_true(kwarg(node, "shell")):
            out.append(_f("shell-injection", Severity.HIGH, cf, node.lineno, f"`{name}(..., shell=True)` runs through the shell",
                          "Pass an argument list without shell=True."))
        elif name in ("os.system", "os.popen"):
            out.append(_f("shell-injection", Severity.HIGH, cf, node.lineno, f"`{name}()` runs a shell command",
                          "Use subprocess.run([...]) with an argument list."))
        elif name in ("pickle.load", "pickle.loads", "marshal.loads", "dill.loads"):
            out.append(_f("unsafe-deserialisation", Severity.HIGH, cf, node.lineno, f"`{name}()` can execute code from untrusted data",
                          "Use a data-only format such as JSON."))
        elif name in ("yaml.load",) and not any(k.arg == "Loader" and "Safe" in ast.unparse(k.value) for k in node.keywords):
            out.append(_f("unsafe-deserialisation", Severity.HIGH, cf, node.lineno, "`yaml.load` without SafeLoader can construct arbitrary objects",
                          "Use yaml.safe_load()."))
        elif is_false(kwarg(node, "verify")) and name.split(".")[0] in ("requests", "httpx", "session", "client"):
            out.append(_f("tls-verification-disabled", Severity.MEDIUM, cf, node.lineno, "TLS certificate verification is disabled",
                          "Remove verify=False or point verify at a CA bundle."))
        elif name in ("hashlib.md5", "hashlib.sha1"):
            out.append(_f("weak-hash", Severity.LOW, cf, node.lineno, f"`{name}` is not collision-resistant",
                          "Use hashlib.sha256 (or bcrypt/argon2 for passwords).", 0.6))
        elif name == "tempfile.mktemp":
            out.append(_f("insecure-tempfile", Severity.MEDIUM, cf, node.lineno, "`tempfile.mktemp` is race-prone",
                          "Use tempfile.NamedTemporaryFile or mkstemp."))
        elif last in ("execute", "executemany", "raw") and node.args and _is_dynamic_string(node.args[0]) \
                and SQL_KEYWORDS.search(_string_text(node.args[0]) or ast.unparse(node.args[0])):
            out.append(_f("sql-injection", Severity.HIGH, cf, node.lineno, "SQL built with string formatting is injectable",
                          "Use parameterised queries: execute(sql, params)."))
        elif last == "run" and is_true(kwarg(node, "debug")):
            out.append(_f("debug-mode", Severity.MEDIUM, cf, node.lineno, "Debug mode enabled in app.run()",
                          "Read debug from configuration and keep it off in production."))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and node.lineno in added and isinstance(node.value, ast.Call):
            target = " ".join(ast.unparse(t) for t in node.targets).lower()
            if call_name(node.value).startswith("random.") and any(w in target for w in ("token", "secret", "password", "nonce", "otp", "salt")):
                out.append(_f("insecure-randomness", Severity.MEDIUM, cf, node.lineno, "`random` is predictable and unsuitable for secrets",
                              "Use the secrets module (secrets.token_urlsafe())."))
    return out


def review_text(cf: ChangedFile) -> list[Finding]:
    out: list[Finding] = []
    is_js = cf.path.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"))
    for line_no, text in cf.added_lines.items():
        for rule, rx, sev in SECRET_PATTERNS:
            if rx.search(text):
                out.append(_f(f"hardcoded-secret/{rule}", sev, cf, line_no, f"Possible {rule.replace('-', ' ')} committed",
                              "Revoke it, remove it from history and load it from a secret store or environment variable."))
        m = ASSIGNED_SECRET.search(text)
        if m and not PLACEHOLDER.search(m.group(2)) and not cf.is_test and entropy(m.group(2)) >= 3.0:
            out.append(_f("hardcoded-secret/assignment", Severity.HIGH, cf, line_no, f"`{m.group(1)}` looks like a hard-coded credential",
                          "Load secrets from environment variables or a secret manager.", 0.7))
        if is_js:
            for rule, rx, sev, msg in JS_RISKS:
                if rx.search(text):
                    out.append(_f(rule, sev, cf, line_no, msg, "", 0.75))
    return out


def run(files: list[ChangedFile]) -> tuple[list[Finding], str]:
    findings: list[Finding] = []
    for cf in files:
        if cf.status == "deleted":
            continue
        findings += review_text(cf)
        tree = parse(cf)
        if tree is not None:
            findings += review_python(cf, tree)
    high = sum(f.severity >= Severity.HIGH for f in findings)
    note = f"{len(findings)} security issue(s), {high} high or critical." if findings else "No security issues in the changed lines."
    return findings, note
