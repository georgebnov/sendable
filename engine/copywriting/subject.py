"""Subject presence check.

`copywriting.subject_heuristics` only inspects subjects that exist (length,
case, emoji). It silently passes when the Subject header is missing or
empty. Empty subjects are themselves a strong spam signal and a known
Gmail/Yahoo/Outlook tagging trigger, so we surface them as their own
finding here.
"""

from __future__ import annotations

from ..parse import ParsedEmail
from ..report import Finding
from ..severity import Severity


async def run(email: ParsedEmail) -> list[Finding]:
    subj = email.subject
    if subj is None or not subj.strip():
        return [
            Finding(
                check="content.subject_present",
                severity=Severity.HIGH,
                passed=False,
                message="Subject is empty or missing — strong spam signal.",
                details={"subject": subj},
            )
        ]
    return [
        Finding(
            check="content.subject_present",
            severity=Severity.INFO,
            passed=True,
            message=f"Subject present ({len(subj)} chars).",
            details={"chars": len(subj)},
        )
    ]
