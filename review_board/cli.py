"""review-board CLI.

    review-board --git main                 # review main...HEAD in the current repo
    review-board --git main..feature --repo ../app
    review-board --diff changes.patch
    review-board --pr owner/repo#42         # public PRs work without a token
    review-board --pr owner/repo#42 --post  # post as a PR review (needs GITHUB_TOKEN with write access)

Exit code: 0, or 1 when a finding reaches --fail-on (useful as a CI gate), 2 on usage/input errors.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import httpx

from .board import review
from .diff import SourceError, from_git, from_github_pr, parse_unified_diff
from .models import Severity
from .report import to_json, to_markdown, to_sarif


def post_github_review(meta: dict, markdown: str, verdict: str, findings, token: str) -> str:
    """Submit a PR review with inline comments on changed lines. Only called with --post."""
    event = {"request_changes": "REQUEST_CHANGES", "comment": "COMMENT", "approve": "COMMENT"}[verdict]
    comments = [{"path": f.path, "line": f.line, "side": "RIGHT", "body": f"**{f.severity.label}** · {f.message}\n\n{f.suggestion}".strip()}
                for f in findings if f.line][:30]
    resp = httpx.post(
        f"https://api.github.com/repos/{meta['owner']}/{meta['repo']}/pulls/{meta['number']}/reviews",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "User-Agent": "multi-agent-code-review-board"},
        json={"commit_id": meta["head_sha"], "body": markdown, "event": event, "comments": comments}, timeout=30)
    resp.raise_for_status()
    return resp.json().get("html_url", "")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="review-board", description="Parallel multi-agent code review of a diff.")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--git", metavar="BASE[..HEAD]", help="review BASE...HEAD of a local repository")
    src.add_argument("--diff", type=Path, help="review a unified diff file ('-' for stdin)")
    src.add_argument("--pr", help="review a GitHub pull request: owner/repo#123 or URL")
    p.add_argument("--repo", default=".", help="repository path for --git (default: current directory)")
    p.add_argument("--format", choices=["markdown", "json", "sarif"], default="markdown")
    p.add_argument("--out", type=Path, help="write the report to a file")
    p.add_argument("--fail-on", choices=[s.label for s in Severity] + ["never"], default="never",
                   help="exit 1 if any finding has at least this severity")
    p.add_argument("--min-severity", choices=[s.label for s in Severity], default="info")
    p.add_argument("--per-file-cap", type=int, default=10)
    p.add_argument("--post", action="store_true", help="with --pr: post the review to GitHub (requires GITHUB_TOKEN)")
    args = p.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    meta = None
    try:
        if args.git:
            base, _, head = args.git.partition("..")
            files = from_git(args.repo, base, head or "HEAD")
        elif args.diff:
            text = sys.stdin.read() if str(args.diff) == "-" else args.diff.read_text(encoding="utf-8")
            files = parse_unified_diff(text)
        else:
            files, meta = from_github_pr(args.pr)
    except (SourceError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.post and not meta:
        print("error: --post only works with --pr", file=sys.stderr)
        return 2

    result, timings = review(files, per_file_cap=args.per_file_cap, min_severity=Severity[args.min_severity.upper()])
    title = f"Multi-agent review: {meta['title']}" if meta else "Multi-agent code review"
    rendered = {"markdown": lambda: to_markdown(result, title), "json": lambda: to_json(result), "sarif": lambda: to_sarif(result)}[args.format]()
    if args.out:
        args.out.write_text(rendered, encoding="utf-8")
        print(f"report written to {args.out}", file=sys.stderr)
    else:
        print(rendered)
    print("agent timings (ms): " + ", ".join(f"{k} {v}" for k, v in timings.items()), file=sys.stderr)

    if args.post:
        token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
        if not token:
            print("error: --post needs GITHUB_TOKEN", file=sys.stderr)
            return 2
        try:
            print(f"review posted: {post_github_review(meta, to_markdown(result, title), result.verdict, result.findings, token)}", file=sys.stderr)
        except httpx.HTTPError as exc:
            print(f"error: posting the review failed: {exc}", file=sys.stderr)
            return 2

    if args.fail_on != "never" and any(f.severity >= Severity[args.fail_on.upper()] for f in result.findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
