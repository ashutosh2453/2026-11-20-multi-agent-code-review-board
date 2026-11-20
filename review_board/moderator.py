"""Moderator agent: reconcile the specialists' findings into one prioritised review."""

from __future__ import annotations

from collections import Counter, defaultdict

from .models import ChangedFile, Finding, Review, Severity


def _score(f: Finding) -> float:
    return int(f.severity) * f.confidence


def moderate(files: list[ChangedFile], findings: list[Finding], notes: dict[str, str], per_file_cap: int = 10,
             min_severity: Severity = Severity.INFO) -> Review:
    # 1. Merge exact duplicates (same file, line and rule) reported by different agents.
    merged: dict[tuple, Finding] = {}
    for f in findings:
        if f.severity < min_severity:
            continue
        k = f.key()
        if k in merged:
            keep = merged[k]
            if _score(f) > _score(keep):
                f.also_flagged_by = sorted(set(keep.also_flagged_by + [keep.agent]))
                merged[k] = f
            elif f.agent != keep.agent and f.agent not in keep.also_flagged_by:
                keep.also_flagged_by.append(f.agent)
        else:
            merged[k] = f

    # 2. Corroboration: a line that several agents independently object to more likely needs
    #    attention, so confidence rises slightly. Different issues stay separate findings;
    #    `also_flagged_by` is reserved for the *same* rule reported by more than one agent.
    by_line: dict[tuple, list[Finding]] = defaultdict(list)
    for f in merged.values():
        if f.line is not None:
            by_line[(f.path, f.line)].append(f)
    for group in by_line.values():
        agents = {f.agent for f in group}
        if len(agents) > 1:
            for f in group:
                f.confidence = min(1.0, f.confidence + 0.05 * (len(agents) - 1))

    # 3. Noise budget per file: keep the most important findings, report how many were dropped.
    per_file: dict[str, list[Finding]] = defaultdict(list)
    for f in merged.values():
        per_file[f.path].append(f)
    kept: list[Finding] = []
    suppressed = 0
    for path, items in per_file.items():
        items.sort(key=lambda f: (-_score(f), f.line or 0))
        kept += items[:per_file_cap]
        suppressed += max(0, len(items) - per_file_cap)
    kept.sort(key=lambda f: (-int(f.severity), f.path, f.line or 0))

    # 4. Verdict.
    worst = max((f.severity for f in kept), default=None)
    if worst is not None and worst >= Severity.HIGH:
        verdict = "request_changes"
    elif worst is not None and worst >= Severity.MEDIUM:
        verdict = "comment"
    else:
        verdict = "approve"

    sev_counts = Counter(f.severity.label for f in kept)
    agent_counts = Counter(f.agent for f in kept)
    added = sum(len(f.added_lines) for f in files)
    stats = {
        "files_changed": len(files), "lines_added": added, "lines_removed": sum(f.removed_count for f in files),
        "findings": len(kept), "suppressed": suppressed,
        "by_severity": {s.label: sev_counts.get(s.label, 0) for s in sorted(Severity, reverse=True)},
        "by_agent": dict(agent_counts),
    }
    if not kept:
        summary = f"No issues found across {len(files)} changed file(s) (+{added} lines)."
    else:
        top = kept[0]
        headline = {"request_changes": "Changes requested", "comment": "Looks mostly fine, with comments", "approve": "Approved with minor notes"}[verdict]
        summary = (f"{headline}: {len(kept)} finding(s) across {len(files)} file(s) (+{added} lines). "
                   f"Most important: {top.message} ({top.path}{f':{top.line}' if top.line else ''}).")
    return Review(verdict, summary, kept, stats, notes)
