"""Urgency-language positioning check.

David's rule: urgency closes, it doesn't open. Lead with urgency and
the reader reads desperation; lead with substance and pay off with
urgency and the reader reads scarcity. Same words, opposite frame.

Implementation: scan the body narrative for an urgency-phrase
vocabulary. For each match, compute position = char_offset /
len(body). Any match landing in the first 40% of the body fires
MEDIUM. Matches in the last 60% are fine.

Body source: joined `body_blocks` + P.S. (P.S. sits at the end so
P.S. urgency never trips the rule). Greeting / signature / footer
are excluded by the extractor.
"""

from __future__ import annotations

import re

from ..parse import ParsedEmail
from ..report import Finding
from ..severity import Severity
from .extract import extract_structured

# Urgency phrases as compiled regexes. Word-boundaries on single words,
# verbatim phrases for multi-word.
_URGENCY_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("limited time", re.compile(r"\blimited\s+time\b", re.IGNORECASE)),
    ("act now", re.compile(r"\bact\s+now\b", re.IGNORECASE)),
    ("expires", re.compile(r"\bexpires?\b|\bexpiring\b", re.IGNORECASE)),
    ("last chance", re.compile(r"\blast\s+chance\b", re.IGNORECASE)),
    ("hurry", re.compile(r"\bhurry\b", re.IGNORECASE)),
    ("don't miss", re.compile(r"\bdon'?t\s+miss\b|\bdo\s+not\s+miss\b", re.IGNORECASE)),
    ("offer ends", re.compile(r"\boffer\s+ends?\b", re.IGNORECASE)),
    ("today only", re.compile(r"\btoday\s+only\b", re.IGNORECASE)),
    ("spots left", re.compile(r"\bspots?\s+left\b", re.IGNORECASE)),
    ("closing soon", re.compile(r"\bclosing\s+soon\b", re.IGNORECASE)),
    ("deadline", re.compile(r"\bdeadline\b", re.IGNORECASE)),
    ("while supplies last", re.compile(r"\bwhile\s+supplies\s+last\b", re.IGNORECASE)),
)

_FRONT_FRACTION = 0.40


async def run(email: ParsedEmail) -> list[Finding]:
    structured = extract_structured(email)
    parts = list(structured.body_blocks)
    if structured.ps:
        parts.append(structured.ps)
    body = "\n\n".join(parts)
    total = len(body)

    if total == 0:
        return [
            Finding(
                check="copywriting.urgency_position",
                severity=Severity.INFO,
                passed=True,
                message="No body content to scan for urgency positioning.",
                details={},
            )
        ]

    front_hits: list[dict] = []
    late_hits: list[dict] = []
    for label, rx in _URGENCY_PATTERNS:
        for m in rx.finditer(body):
            pos = m.start() / total
            entry = {
                "phrase": label,
                "matched_text": m.group(0),
                "char_offset": m.start(),
                "position_pct": round(pos * 100, 1),
            }
            (front_hits if pos < _FRONT_FRACTION else late_hits).append(entry)

    if front_hits:
        labels = sorted({h["phrase"] for h in front_hits})
        return [
            Finding(
                check="copywriting.urgency_position",
                severity=Severity.MEDIUM,
                passed=False,
                message=(
                    f"Urgency language in the opening 40% of the body "
                    f"({', '.join(labels)}). Urgency closes, it doesn't "
                    f"open: leading with it reads as desperate. Move "
                    f"these phrases past the midpoint so they pay off "
                    f"a built-up case."
                ),
                details={
                    "front_hits": front_hits,
                    "late_hits": late_hits,
                    "front_threshold_pct": _FRONT_FRACTION * 100,
                    "body_chars": total,
                },
            )
        ]

    if late_hits:
        return [
            Finding(
                check="copywriting.urgency_position",
                severity=Severity.INFO,
                passed=True,
                message=(
                    f"Urgency language present but positioned in the closing "
                    f"60% of the body ({len(late_hits)} hit(s))."
                ),
                details={
                    "late_hits": late_hits,
                    "front_threshold_pct": _FRONT_FRACTION * 100,
                    "body_chars": total,
                },
            )
        ]

    return [
        Finding(
            check="copywriting.urgency_position",
            severity=Severity.INFO,
            passed=True,
            message="No urgency language detected.",
            details={"body_chars": total},
        )
    ]
