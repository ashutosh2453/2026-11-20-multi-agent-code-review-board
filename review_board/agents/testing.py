"""Test-coverage reviewer: do changed public functions come with test changes that exercise them?"""

from __future__ import annotations

import re

from ..models import ChangedFile, Finding, Severity
from .common import parse, touched_functions

NAME = "tests"


def run(files: list[ChangedFile]) -> tuple[list[Finding], str]:
    test_files = [f for f in files if f.is_test and f.status != "deleted"]
    test_text = "\n".join((f.new_source or "\n".join(f.added_lines.values())) for f in test_files)
    findings: list[Finding] = []
    untested_total = changed_total = 0
    for cf in files:
        if cf.is_test or cf.status == "deleted":
            continue
        tree = parse(cf)
        if tree is None:
            continue
        public = [tf for tf in touched_functions(cf, tree)
                  if not any(part.startswith("_") for part in tf.qualname.split("."))]
        if not public:
            continue
        changed_total += len(public)
        untested = [tf for tf in public if not re.search(rf"\b{re.escape(tf.qualname.split('.')[-1])}\b", test_text)]
        untested_total += len(untested)
        if not untested:
            continue
        names = ", ".join(f"`{tf.qualname}`" for tf in untested[:5]) + (" …" if len(untested) > 5 else "")
        new_ones = [tf for tf in untested if tf.def_line_added]
        sev = Severity.MEDIUM if new_ones else Severity.LOW
        where = "no test files were changed" if not test_files else "the changed tests never reference them"
        findings.append(Finding(NAME, "missing-tests", sev, cf.path, untested[0].node.lineno,
                                f"{len(untested)} changed public function(s) without tests ({where}): {names}",
                                "Add or update tests that call these functions.", 0.75))
    if not changed_total:
        note = "No changed public Python functions."
    else:
        note = f"{changed_total - untested_total}/{changed_total} changed public functions are referenced by changed tests."
    return findings, note
