"""Render a review as Markdown, JSON or SARIF 2.1.0 (GitHub code scanning)."""

from __future__ import annotations

import json

from . import __version__
from .models import Review, Severity

ICON = {Severity.CRITICAL: "🛑", Severity.HIGH: "🔴", Severity.MEDIUM: "🟠", Severity.LOW: "🟡", Severity.INFO: "ℹ️"}
VERDICT = {"request_changes": "❌ Request changes", "comment": "💬 Comment", "approve": "✅ Approve"}


def to_markdown(r: Review, title: str = "Multi-agent code review") -> str:
    s = r.stats
    lines = [f"## {title}", "", f"**Verdict: {VERDICT[r.verdict]}**", "", r.summary, "",
             f"`{s['files_changed']}` files · `+{s['lines_added']} / -{s['lines_removed']}` lines · "
             + " · ".join(f"{k}: {v}" for k, v in s["by_severity"].items() if v), ""]
    if r.findings:
        lines += ["| | Location | Finding | Agent |", "|---|---|---|---|"]
        for f in r.findings:
            loc = f"`{f.path}:{f.line}`" if f.line else f"`{f.path}`"
            # No backslashes inside f-string expressions: that needs Python 3.12+ (PEP 701).
            escaped_suggestion = f.suggestion.replace("|", "\\|")
            msg = f.message.replace("|", "\\|") + (f"<br>↳ {escaped_suggestion}" if f.suggestion else "")
            agents = f.agent + (f" (+{', '.join(f.also_flagged_by)})" if f.also_flagged_by else "")
            lines.append(f"| {ICON[f.severity]} {f.severity.label} | {loc} | {msg} | {agents} |")
        lines.append("")
    if s.get("suppressed"):
        lines += [f"_{s['suppressed']} lower-priority finding(s) suppressed by the per-file noise budget._", ""]
    lines += ["<details><summary>Reviewer notes</summary>", ""]
    lines += [f"- **{name}**: {note}" for name, note in r.agent_notes.items()]
    lines += ["", "</details>"]
    return "\n".join(lines) + "\n"


def to_json(r: Review) -> str:
    return json.dumps(r.to_dict(), indent=2)


SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note"}


def to_sarif(r: Review) -> str:
    rules: dict[str, dict] = {}
    results = []
    for f in r.findings:
        rule_id = f"{f.agent}/{f.rule}"
        rules.setdefault(rule_id, {"id": rule_id, "shortDescription": {"text": f.rule.replace("-", " ")},
                                   "properties": {"tags": [f.agent]}})
        result = {
            "ruleId": rule_id,
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f.message + (f" {f.suggestion}" if f.suggestion else "")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path},
                                                **({"region": {"startLine": f.line}} if f.line else {})}}],
            "properties": {"severity": f.severity.label, "confidence": round(f.confidence, 2)},
        }
        results.append(result)
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "multi-agent-code-review-board", "version": __version__,
                                      "informationUri": "https://github.com/ashutosh2453/2026-11-20-multi-agent-code-review-board",
                                      "rules": list(rules.values())}},
                  "results": results}],
    }
    return json.dumps(sarif, indent=2)
