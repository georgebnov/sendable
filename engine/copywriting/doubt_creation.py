"""Doubt-creation phrase detection.

David's rule: naming the doubt creates the doubt. Phrases like "if
you're still unsure" or "no pressure" plant the exact hesitation the
marketer is trying to head off. Sales psychology: addressing a doubt
the reader didn't yet have makes the reader retroactively own it.

Implementation: substring scan over the body narrative. Each phrase is
matched verbatim (case-insensitive, whitespace-flexible). One exception
— "no pressure" is contextually flagged: only when it sits in the
closing region (last 40% of body OR inside the P.S.), since the spec
notes the phrase is doubt-creating specifically in closing context.
"""

from __future__ import annotations

import re

from ..parse import ParsedEmail
from ..report import Finding
from ..severity import Severity
from .extract import extract_structured

_DOUBT_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("if you're still unsure", re.compile(r"\bif\s+you'?re\s+still\s+unsure\b", re.IGNORECASE)),
    ("if you have any doubts", re.compile(r"\bif\s+you\s+have\s+any\s+doubts?\b", re.IGNORECASE)),
    ("if you're not sure", re.compile(r"\bif\s+you'?re\s+not\s+sure\b", re.IGNORECASE)),
    ("it's completely up to you", re.compile(r"\bit'?s\s+completely\s+up\s+to\s+you\b", re.IGNORECASE)),
    ("it's up to you", re.compile(r"\bit'?s\s+up\s+to\s+you\b", re.IGNORECASE)),
    ("if you're on the fence", re.compile(r"\bif\s+you'?re\s+on\s+the\s+fence\b", re.IGNORECASE)),
    ("if this isn't for you", re.compile(r"\bif\s+this\s+isn'?t\s+for\s+you\b", re.IGNORECASE)),
    ("if you think you wasted", re.compile(r"\bif\s+you\s+think\s+you\s+wasted\b", re.IGNORECASE)),
    ("if you're skeptical", re.compile(r"\bif\s+you'?re\s+skeptical\b", re.IGNORECASE)),
    ("only if you want to", re.compile(r"\bonly\s+if\s+you\s+want\s+to\b", re.IGNORECASE)),
)

_NO_PRESSURE_RX = re.compile(r"\bno\s+pressure\b", re.IGNORECASE)

_CLOSING_FRACTION = 0.60  # last 40% = position ≥ 0.60


async def run(email: ParsedEmail) -> list[Finding]:
    structured = extract_structured(email)
    body_parts = list(structured.body_blocks)
    body = "\n\n".join(body_parts)
    ps = structured.ps or ""
    # P.S. lines are often absorbed by the signature peel when short
    # (≤6 words). Treat signature as part of the closing-context region
    # for the "no pressure" qualifier so a short P.S. inside signature
    # still flags.
    sig = structured.signature or ""
    total = len(body)

    hits: list[str] = []

    haystack = "\n\n".join(p for p in [body, ps, sig] if p)
    for label, rx in _DOUBT_PATTERNS:
        if rx.search(haystack):
            hits.append(label)

    # "no pressure" — closing-context only. Closing region = P.S. or
    # signature block (both end-of-email) OR last 40% of body.
    closing_blob = "\n\n".join(p for p in [ps, sig] if p)
    if closing_blob and _NO_PRESSURE_RX.search(closing_blob):
        hits.append("no pressure (closing)")
    elif total and _NO_PRESSURE_RX.search(body):
        for m in _NO_PRESSURE_RX.finditer(body):
            if m.start() / total >= _CLOSING_FRACTION:
                hits.append("no pressure (closing)")
                break

    if hits:
        return [
            Finding(
                check="copywriting.doubt_creation",
                severity=Severity.MEDIUM,
                passed=False,
                message=(
                    f"Doubt-creating phrase(s) detected: {', '.join(hits)}. "
                    f"Naming the doubt creates the doubt — the reader "
                    f"adopts hesitation that wasn't there. Cut the "
                    f"phrase; lead with confidence about the next step."
                ),
                details={"matches": hits},
            )
        ]

    return [
        Finding(
            check="copywriting.doubt_creation",
            severity=Severity.INFO,
            passed=True,
            message="No doubt-creating phrases detected.",
            details={},
        )
    ]
