"""Generic-opener detection on body lead.

Spam-filter NLP models statistically associate certain filler openings
with mass email ("I hope this finds you well", "Just following up",
"To whom it may concern"). Their presence is a cheap, deterministic
signal that the writer skipped the work of a real hook.

Check inspects the first 120 chars of the body narrative (lowercased,
whitespace collapsed). Greeting line is prepended to that window before
the scan — several flag phrases ARE greeting-shaped ("Dear friend,",
"Dear valued client,", "To whom it may concern,") and would otherwise
be peeled into `StructuredEmail.greeting` and missed.
"""

from __future__ import annotations

import re

from ..parse import ParsedEmail
from ..report import Finding
from ..severity import Severity
from .extract import extract_structured

# Phrases sourced from spam-filter NLP literature on mass-email lexicons.
# Lowercased; matched as substrings against the lowercased opener window.
_FLAG_PHRASES = (
    "i hope this email finds you",
    "i hope this message finds you",
    "i'm reaching out",
    "i am reaching out",
    "just following up",
    "just wanted to follow up",
    "i wanted to touch base",
    "as per my last",
    "i hope you're doing well",
    "i hope you are doing well",
    "i wanted to take a moment",
    "dear friend",
    "dear valued",
    "to whom it may concern",
    "good day",
)

_WINDOW = 120


async def run(email: ParsedEmail) -> list[Finding]:
    structured = extract_structured(email)
    if not structured.greeting and not structured.body_blocks:
        return [
            Finding(
                check="copywriting.generic_opener",
                severity=Severity.INFO,
                passed=True,
                message="No body content to inspect for generic openers.",
                details={"window": _WINDOW},
            )
        ]

    # Prepend greeting so greeting-shaped flag phrases (e.g. "Dear
    # friend,", "To whom it may concern,") still hit even though the
    # extractor peels them out of body_blocks.
    parts = [structured.greeting] if structured.greeting else []
    if structured.body_blocks:
        parts.append(structured.body_blocks[0])
    lead = re.sub(r"\s+", " ", " ".join(parts)).strip().lower()
    window = lead[:_WINDOW]

    hits = [p for p in _FLAG_PHRASES if p in window]

    if hits:
        return [
            Finding(
                check="copywriting.generic_opener",
                severity=Severity.MEDIUM,
                passed=False,
                message=(
                    f"Opening uses generic filler phrase: "
                    f'"{hits[0]}". Spam-filter NLP models flag these '
                    f"as mass-email markers. Open with something specific "
                    f"to the recipient or the news instead."
                ),
                details={
                    "matches": hits,
                    "opener": window,
                    "window": _WINDOW,
                },
            )
        ]

    return [
        Finding(
            check="copywriting.generic_opener",
            severity=Severity.INFO,
            passed=True,
            message="Opener avoids known filler phrases.",
            details={"opener": window, "window": _WINDOW},
        )
    ]
