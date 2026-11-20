"""Shared data model: changed files, findings and the review verdict."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass
class ChangedFile:
    path: str
    status: str  # added | modified | deleted | renamed
    added_lines: dict[int, str] = field(default_factory=dict)  # new-file line number -> text
    removed_count: int = 0
    new_source: str | None = None  # full post-change content when available
    crlf_added: int = 0  # added lines that ended with CRLF
    crlf_removed: int = 0  # removed lines that ended with CRLF

    @property
    def is_python(self) -> bool:
        return self.path.endswith(".py")

    @property
    def is_test(self) -> bool:
        name = self.path.replace("\\", "/").rsplit("/", 1)[-1]
        return "/tests/" in f"/{self.path}" or name.startswith("test_") or name.endswith("_test.py") or ".test." in name or ".spec." in name


@dataclass
class Finding:
    agent: str
    rule: str
    severity: Severity
    path: str
    line: int | None
    message: str
    suggestion: str = ""
    confidence: float = 0.9
    also_flagged_by: list[str] = field(default_factory=list)

    def key(self) -> tuple:
        return (self.path, self.line, self.rule)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.label
        return d


@dataclass
class Review:
    verdict: str  # approve | comment | request_changes
    summary: str
    findings: list[Finding]
    stats: dict
    agent_notes: dict[str, str]

    def to_dict(self) -> dict:
        return {"verdict": self.verdict, "summary": self.summary, "stats": self.stats,
                "agent_notes": self.agent_notes, "findings": [f.to_dict() for f in self.findings]}
