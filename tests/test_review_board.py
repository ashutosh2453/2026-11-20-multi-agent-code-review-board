import json
import subprocess
import textwrap
from pathlib import Path

import httpx
import pytest
import respx

from review_board.agents import complexity, maintainability, security, testing
from review_board.board import DEFAULT_AGENTS, review
from review_board.cli import main
from review_board.diff import SourceError, from_git, from_github_pr, parse_pr_ref, parse_unified_diff
from review_board.models import ChangedFile, Finding, Severity
from review_board.moderator import moderate
from review_board.report import to_markdown, to_sarif


def added_file(path: str, source: str, status: str = "added") -> ChangedFile:
    """A ChangedFile where every line of `source` was added."""
    src = textwrap.dedent(source).lstrip("\n")
    return ChangedFile(path, status, {i: line for i, line in enumerate(src.split("\n"), start=1)}, 0, src)


def rules(findings) -> set[str]:
    return {f.rule for f in findings}


# ---------------------------------------------------------------- diff parsing

DIFF = """diff --git a/app/db.py b/app/db.py
index 1..2 100644
--- a/app/db.py
+++ b/app/db.py
@@ -10,3 +10,4 @@ def get(user):
 conn = connect()
-cur.execute("SELECT 1")
+cur.execute(f"SELECT * FROM users WHERE name = '{user}'")
+print(user)
 return cur
diff --git a/old.txt b/old.txt
deleted file mode 100644
--- a/old.txt
+++ /dev/null
@@ -1 +0,0 @@
-gone
diff --git a/new.js b/new.js
new file mode 100644
--- /dev/null
+++ b/new.js
@@ -0,0 +1,2 @@
+el.innerHTML = userInput;
+console.log("debug");
"""


def test_parse_unified_diff_tracks_new_line_numbers_and_status():
    files = {f.path: f for f in parse_unified_diff(DIFF)}
    assert files["app/db.py"].added_lines == {11: "cur.execute(f\"SELECT * FROM users WHERE name = '{user}'\")", 12: "print(user)"}
    assert files["app/db.py"].removed_count == 1
    assert files["old.txt"].status == "deleted"
    assert files["new.js"].status == "added" and set(files["new.js"].added_lines) == {1, 2}


def test_parse_detects_crlf_churn_markers():
    churn = "diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1,2 +1,2 @@\n-a = 1\n-b = 2\n+a = 1\r\n+b = 2\r\n"
    [f] = parse_unified_diff(churn)
    assert (f.crlf_added, f.crlf_removed) == (2, 0)
    assert f.added_lines == {1: "a = 1", 2: "b = 2"}


# ---------------------------------------------------------------- security agent

def test_security_agent_flags_dangerous_python():
    cf = added_file("svc.py", """
        import os, pickle, subprocess, yaml, requests, hashlib, random, tempfile
        def handler(cmd, blob, user, cur):
            eval(cmd)
            subprocess.run(cmd, shell=True)
            os.system(cmd)
            pickle.loads(blob)
            yaml.load(blob)
            yaml.load(blob, Loader=yaml.SafeLoader)
            requests.get("https://x", verify=False)
            hashlib.md5(b"x")
            tempfile.mktemp()
            cur.execute("SELECT * FROM t WHERE id = %s" % user)
            cur.execute("SELECT * FROM t WHERE id = %s", (user,))
            reset_token = random.randint(0, 999999)
    """)
    found, _ = security.run([cf])
    assert rules(found) == {"code-injection", "shell-injection", "unsafe-deserialisation", "tls-verification-disabled", "weak-hash",
                            "insecure-tempfile", "sql-injection", "insecure-randomness"}
    assert sum(f.rule == "unsafe-deserialisation" for f in found) == 2  # pickle + unsafe yaml.load, not the SafeLoader call
    assert sum(f.rule == "sql-injection" for f in found) == 1  # parameterised query is fine


def test_security_agent_finds_secrets_but_not_placeholders():
    cf = added_file("settings.py", """
        AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
        API_KEY = "sk_live_9fA3kQ8zP2xLm7Rt"
        PASSWORD = "changeme-please"
        TOKEN = os.environ["TOKEN"]
    """)
    found, _ = security.run([cf])
    assert {f.rule for f in found} == {"hardcoded-secret/aws-access-key", "hardcoded-secret/assignment"}
    assert all(f.line in (1, 2) for f in found)


def test_security_only_reviews_changed_lines():
    src = "import os\nos.system('ls')\nx = 1\n"
    cf = ChangedFile("a.py", "modified", {3: "x = 1"}, 0, src)
    assert security.run([cf])[0] == []


# ---------------------------------------------------------------- complexity agent

def test_complexity_agent():
    branches = "\n".join(f"    if x == {i} and y:\n        return {i}" for i in range(12))
    deep = "def deep(a):\n    if a:\n        for i in a:\n            while i:\n                with open(i) as f:\n                    if f:\n                        return f\n"
    cf = added_file("m.py", f"def branchy(x, y):\n{branches}\n    return -1\n\n{deep}\ndef many(a, b, c, d, e, f, g):\n    return a\n")
    found, note = complexity.run([cf])
    assert {(f.rule, f.message.split('`')[1]) for f in found} == {
        ("cyclomatic-complexity", "branchy"), ("deep-nesting", "deep"), ("too-many-parameters", "many")}
    cc = next(f for f in found if f.rule == "cyclomatic-complexity")
    assert cc.severity == Severity.HIGH and "complexity 25" in cc.message  # 1 + 12 ifs + 12 `and`s
    assert "branchy" in note


def test_complexity_ignores_untouched_functions():
    src = "def a():\n    return 1\n\ndef b(x, y, z, p, q, r, s):\n    return x\n"
    cf = ChangedFile("m.py", "modified", {2: "    return 1"}, 1, src)
    assert complexity.run([cf])[0] == []


# ---------------------------------------------------------------- tests agent

def test_tests_agent_requires_tests_for_new_public_functions():
    src = added_file("pkg/calc.py", "def add(a, b):\n    return a + b\n\ndef sub(a, b):\n    return a - b\n\ndef _private():\n    return 0\n")
    found, note = testing.run([src])
    assert len(found) == 1 and found[0].severity == Severity.MEDIUM and "`add`, `sub`" in found[0].message
    tests = added_file("tests/test_calc.py", "from pkg.calc import add\n\ndef test_add():\n    assert add(1, 2) == 3\n")
    found, note = testing.run([src, tests])
    assert "`sub`" in found[0].message and "`add`" not in found[0].message
    assert note == "1/2 changed public functions are referenced by changed tests."


# ---------------------------------------------------------------- maintainability agent

def test_maintainability_agent():
    cf = added_file("lib/util.py", """
        def collect(item, bucket=[]):
            '''Collect items.'''
            bucket.append(item)
            try:
                risky()
            except Exception:
                pass
            try:
                risky()
            except:
                raise
            breakpoint()
            print(item)
            # TODO: handle unicode
            return bucket

        def undocumented(a):
            x = a
            y = x
            z = y
            w = z
            return w
    """)
    found, _ = maintainability.run([cf])
    assert rules(found) == {"mutable-default", "swallowed-exception", "bare-except", "debugger-left-in", "print-statement",
                            "todo-added", "missing-docstring"}


def test_print_is_fine_in_scripts():
    cf = added_file("tools/bench.py", "def main():\n    print('hi')\n\nif __name__ == '__main__':\n    print('x')\n    main()\n")
    assert "print-statement" not in rules(maintainability.run([cf])[0])


def test_line_ending_churn_is_flagged():
    cf = ChangedFile("big.py", "modified", {i: f"x{i} = {i}" for i in range(1, 41)}, 40, None, crlf_added=40, crlf_removed=0)
    found, _ = maintainability.run([cf])
    assert found[0].rule == "line-ending-churn" and "LF to CRLF" in found[0].message


# ---------------------------------------------------------------- moderator & board

def test_moderator_merges_duplicates_caps_noise_and_decides():
    fs = [Finding("security", "x", Severity.HIGH, "a.py", 3, "m"), Finding("maintainability", "x", Severity.MEDIUM, "a.py", 3, "m"),
          *[Finding("maintainability", f"n{i}", Severity.LOW, "a.py", 10 + i, "noise") for i in range(12)]]
    r = moderate([ChangedFile("a.py", "modified")], fs, {}, per_file_cap=5)
    assert r.verdict == "request_changes"
    assert r.findings[0].agent == "security" and r.findings[0].also_flagged_by == ["maintainability"]
    assert len(r.findings) == 5 and r.stats["suppressed"] == 8
    assert moderate([], [Finding("t", "r", Severity.MEDIUM, "b.py", 1, "m")], {}).verdict == "comment"
    assert moderate([], [Finding("t", "r", Severity.LOW, "b.py", 1, "m")], {}).verdict == "approve"
    assert moderate([], [], {}).verdict == "approve"


def test_board_runs_all_agents_in_parallel_and_survives_a_broken_agent():
    files = parse_unified_diff(DIFF)
    files[0].new_source = "conn = connect()\n" * 10 + "cur.execute(f\"SELECT * FROM users WHERE name = '{user}'\")\nprint(user)\nreturn cur\n"

    def broken(_files):
        raise RuntimeError("model unavailable")

    r, timings = review(files, agents={**DEFAULT_AGENTS, "llm": broken})
    assert set(timings) == {"security", "complexity", "tests", "maintainability", "llm"}
    assert r.agent_notes["llm"] == "agent failed: RuntimeError: model unavailable"
    assert {"sql-injection", "js-inner-html", "console-log"} <= rules(r.findings)
    assert r.verdict == "request_changes"


# ---------------------------------------------------------------- sources

@pytest.fixture
def repo(tmp_path: Path) -> Path:
    def git(*a):
        subprocess.run(["git", "-C", str(tmp_path), *a], check=True, capture_output=True)
    git("init", "-q", "-b", "main")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "t")
    git("config", "core.autocrlf", "false")
    (tmp_path / "app.py").write_bytes(b"def ok():\n    return 1\n")
    git("add", ".")
    git("commit", "-q", "-m", "base")
    git("checkout", "-q", "-b", "feature")
    (tmp_path / "app.py").write_bytes(b"import os\n\ndef ok():\n    return 1\n\ndef run(cmd):\n    os.system(cmd)\n")
    git("commit", "-q", "-am", "feature")
    return tmp_path


def test_from_git_reviews_a_branch(repo):
    files = from_git(repo, "main", "feature")
    assert [f.path for f in files] == ["app.py"]
    assert files[0].new_source.startswith("import os")
    r, _ = review(files)
    assert any(f.rule == "shell-injection" and f.line == 7 for f in r.findings)
    with pytest.raises(SourceError):
        from_git(repo, "--output=/tmp/x", "feature")
    with pytest.raises(SourceError):
        from_git(repo, "nope", "feature")


def test_parse_pr_ref():
    assert parse_pr_ref("octo/repo#12") == ("octo", "repo", 12)
    assert parse_pr_ref("https://github.com/octo/repo/pull/7") == ("octo", "repo", 7)
    with pytest.raises(SourceError):
        parse_pr_ref("not a pr")


@respx.mock
def test_from_github_pr_fetches_files_and_contents():
    api = "https://api.github.com/repos/octo/app"
    respx.get(f"{api}/pulls/5").mock(return_value=httpx.Response(200, json={"title": "Add runner", "head": {"sha": "abc"}}))
    respx.get(f"{api}/pulls/5/files").mock(return_value=httpx.Response(200, json=[
        {"filename": "run.py", "status": "added", "changes": 2, "patch": "@@ -0,0 +1,2 @@\n+import os\n+os.system(x)",
         "raw_url": "https://raw.example/run.py"}]))
    respx.get("https://raw.example/run.py").mock(return_value=httpx.Response(200, text="import os\nos.system(x)\n"))
    files, meta = from_github_pr("octo/app#5", token="t")
    assert meta == {"owner": "octo", "repo": "app", "number": 5, "title": "Add runner", "head_sha": "abc"}
    assert files[0].added_lines == {1: "import os", 2: "os.system(x)"} and files[0].new_source.startswith("import os")
    respx.get(f"{api}/pulls/6").mock(return_value=httpx.Response(404))
    with pytest.raises(SourceError, match="404"):
        from_github_pr("octo/app#6")


# ---------------------------------------------------------------- reports & CLI

def test_reports():
    r, _ = review(parse_unified_diff(DIFF))
    md = to_markdown(r)
    assert md.startswith("## Multi-agent code review") and "Verdict" in md and "| 🟠 medium |" in md
    sarif = json.loads(to_sarif(r))
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert {x["ruleId"] for x in results} == {rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert all(x["level"] in ("error", "warning", "note") for x in results)


def test_cli_exit_codes(tmp_path, capsys):
    patch = tmp_path / "c.patch"
    patch.write_text(DIFF, encoding="utf-8")
    assert main(["--diff", str(patch), "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["verdict"] == "comment" and out["stats"]["files_changed"] == 3
    assert main(["--diff", str(patch), "--fail-on", "medium"]) == 1
    assert main(["--diff", str(tmp_path / "missing.patch")]) == 2
    assert main(["--diff", str(patch), "--post"]) == 2
