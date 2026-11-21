"""Load a change set from a unified diff, a local git range, or a GitHub pull request."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import httpx

from .models import ChangedFile

HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
MAX_SOURCE_BYTES = 500_000


class SourceError(RuntimeError):
    pass


def parse_unified_diff(text: str) -> list[ChangedFile]:
    """Parse `git diff` output. Tracks new-file line numbers of every added line and CRLF churn."""
    files: list[ChangedFile] = []
    cur: ChangedFile | None = None
    new_line = 0
    # Split on LF only: str.splitlines() also splits on (and drops) CR, which would hide CRLF churn.
    for raw in text.split("\n"):
        if raw.startswith("diff --git "):
            m = re.match(r"diff --git a/(.+?) b/(.+?)\r?$", raw)
            cur = ChangedFile(path=m.group(2) if m else raw.split()[-1].removeprefix("b/"), status="modified")
            files.append(cur)
            continue
        if cur is None:
            continue
        if raw.startswith("new file mode"):
            cur.status = "added"
        elif raw.startswith("deleted file mode"):
            cur.status = "deleted"
        elif raw.startswith("rename to "):
            cur.status = "renamed"
        elif raw.startswith("+++ "):
            target = raw[4:].strip()
            if target != "/dev/null":
                cur.path = target.removeprefix("b/")
        elif raw.startswith("--- "):
            continue
        elif (m := HUNK_RE.match(raw)):
            new_line = int(m.group(1))
        elif raw.startswith("+"):
            body = raw[1:]
            if body.endswith("\r"):
                cur.crlf_added += 1
                body = body[:-1]
            cur.added_lines[new_line] = body
            new_line += 1
        elif raw.startswith("-"):
            cur.removed_count += 1
            if raw.endswith("\r"):
                cur.crlf_removed += 1
        elif raw.startswith(" ") or raw == "":
            new_line += 1
        # "\ No newline at end of file" and other metadata lines are ignored
    return files


EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"  # git's well-known empty tree object
SKIP_DIRS = re.compile(r"(^|/)(node_modules|vendor|dist|build|\.venv|venv|__pycache__|\.git)/")
BINARY_EXT = re.compile(r"\.(png|jpe?g|gif|ico|pdf|zip|gz|mp4|mov|woff2?|ttf|pyc|so|dll|exe|bin|lock)$", re.I)


def _check_ref(ref: str) -> None:
    if not re.fullmatch(r"[\w./@^~{}-]+", ref) or ref.startswith("-"):
        raise SourceError(f"suspicious git ref {ref!r}")


def _git_runner(repo: Path):
    def git(*args: str) -> str:
        try:
            out = subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True).stdout
            # Decode bytes ourselves: text=True would translate CRLF and hide line-ending churn.
            return out.decode("utf-8", errors="replace")
        except FileNotFoundError as exc:
            raise SourceError("git is not installed") from exc
        except subprocess.CalledProcessError as exc:
            raise SourceError(exc.stderr.decode("utf-8", errors="replace").strip() or "git failed") from exc
    return git


def from_git(repo: str | Path, base: str, head: str = "HEAD") -> list[ChangedFile]:
    """Diff base...head in a local repository and attach the full head version of each file.

    Falls back to a direct base..head diff when the two have no merge base, e.g. when the
    base is git's empty tree (review a whole history) or the branches are unrelated.
    """
    repo = Path(repo)
    for ref in (base, head):
        _check_ref(ref)
    git = _git_runner(repo)
    try:
        diff = git("diff", "--no-color", "--unified=3", f"{base}...{head}")
    except SourceError as exc:
        if "merge base" not in str(exc).lower() and base != EMPTY_TREE:
            raise
        diff = git("diff", "--no-color", "--unified=3", base, head)
    files = parse_unified_diff(diff)
    for f in files:
        if f.status != "deleted":
            try:
                content = git("show", f"{head}:{f.path}").replace("\r\n", "\n")
                f.new_source = content if len(content) <= MAX_SOURCE_BYTES else None
            except SourceError:
                f.new_source = None
    return files


def from_snapshot(repo: str | Path, ref: str = "HEAD", max_files: int = 2000) -> list[ChangedFile]:
    """Audit every tracked text file at `ref` as if all its lines were newly added.

    Useful for a first review of an existing codebase. Vendored/build directories and
    binary files are skipped; `max_files` bounds the work.
    """
    _check_ref(ref)
    git = _git_runner(Path(repo))
    paths = [p for p in git("ls-tree", "-r", "--name-only", ref).split("\n")
             if p and not SKIP_DIRS.search(p) and not BINARY_EXT.search(p)]
    if len(paths) > max_files:
        raise SourceError(f"{len(paths)} files at {ref}; raise --max-files or review a diff instead")
    files: list[ChangedFile] = []
    for path in paths:
        try:
            content = git("show", f"{ref}:{path}")
        except SourceError:
            continue
        if "\x00" in content[:8000] or len(content) > MAX_SOURCE_BYTES:
            continue  # binary or too large
        normalised = content.replace("\r\n", "\n")
        lines = normalised.split("\n")
        if lines and lines[-1] == "":
            lines = lines[:-1]
        files.append(ChangedFile(path, "added", {i: line for i, line in enumerate(lines, start=1)}, 0, normalised))
    return files


def parse_pr_ref(ref: str) -> tuple[str, str, int]:
    m = re.fullmatch(r"(?:https://github\.com/)?([\w.-]+)/([\w.-]+)(?:#|/pull/)(\d+)/?", ref.strip())
    if not m:
        raise SourceError("expected owner/repo#123 or a github.com pull request URL")
    return m.group(1), m.group(2), int(m.group(3))


def from_github_pr(ref: str, token: str | None = None, client: httpx.Client | None = None) -> tuple[list[ChangedFile], dict]:
    """Fetch a PR's changed files (with patches) and head contents via the GitHub REST API."""
    owner, repo, number = parse_pr_ref(ref)
    token = token or os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "multi-agent-code-review-board"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    http = client or httpx.Client(timeout=30, headers=headers, base_url="https://api.github.com")
    try:
        pr = http.get(f"/repos/{owner}/{repo}/pulls/{number}")
        pr.raise_for_status()
        pr_data = pr.json()
        files: list[ChangedFile] = []
        page = 1
        while True:
            resp = http.get(f"/repos/{owner}/{repo}/pulls/{number}/files", params={"per_page": 100, "page": page})
            resp.raise_for_status()
            batch = resp.json()
            for item in batch:
                status = {"removed": "deleted"}.get(item["status"], item["status"])
                patch = item.get("patch") or ""
                parsed = parse_unified_diff(f"diff --git a/{item['filename']} b/{item['filename']}\n+++ b/{item['filename']}\n{patch}")
                cf = parsed[0] if parsed else ChangedFile(item["filename"], status)
                cf.status = status
                if status != "deleted" and item.get("raw_url") and item.get("changes", 0) < 5000:
                    raw = http.get(item["raw_url"], follow_redirects=True)
                    if raw.status_code == 200 and len(raw.content) <= MAX_SOURCE_BYTES:
                        cf.new_source = raw.text
                files.append(cf)
            if len(batch) < 100:
                break
            page += 1
    except httpx.HTTPStatusError as exc:
        raise SourceError(f"GitHub API returned {exc.response.status_code} for {exc.request.url.path}") from exc
    except httpx.HTTPError as exc:
        raise SourceError(f"GitHub API request failed: {exc}") from exc
    meta = {"owner": owner, "repo": repo, "number": number, "title": pr_data.get("title"), "head_sha": pr_data.get("head", {}).get("sha")}
    return files, meta
