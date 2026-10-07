"""Subject-line word count check.

Mobile clients truncate subject lines aggressively (Gmail iOS ≈ 35 chars,
Apple Mail ≈ 30 chars in portrait, ≈ 60 chars landscape). Beyond ~14
words the line is guaranteed to clip on most reading surfaces; below ~4
words the subject lacks the specificity a reader needs to decide
whether to open.

Bands:
  • ≤3 words   → LOW     (too vague — low signal, opens drop)
  • 4–5 words  → INFO    (borderline; specific subjects can still work)
  • 6–10 words → INFO    (sweet spot per email-marketing research)
  • 11–14 words→ MEDIUM  (wordy; truncation risk on small viewports)
  • ≥15 words  → MEDIUM  (truncated on every mobile client)

Reply/forward prefixes (`Re:`, `Fwd:`, `Fw:`) are stripped before
counting — they're separate signal grade by `fake_reply_subject` and
shouldn't inflate the word count toward MEDIUM. Empty/missing subjects
are handled by `content.subject_present` and skipped here.
"""

from __future__ import annotations

import re

from ..parse import ParsedEmail
from ..report import Finding
from ..severity import Severity

_REPLY_PREFIX_RX = re.compile(
    r"^\s*(?:(?:re|fwd|fw)\s*:\s*)+",
    re.IGNORECASE,
)


def _strip_reply_prefix(subject: str) -> str:
    prev = None
    out = subject
    # Iteratively strip in case of "Re: Fwd: Re: ...".
    while prev != out:
        prev = out
        out = _REPLY_PREFIX_RX.sub("", out, count=1)
    return out


def _count_words(subject: str) -> int:
    return len([w for w in subject.split() if any(c.isalnum() for c in w)])


async def run(email: ParsedEmail) -> list[Finding]:
    subj = (email.subject or "").strip()
    if not subj:
        return [
            Finding(
                check="copywriting.subject_word_count",
                severity=Severity.INFO,
                passed=True,
                message="No subject to grade (covered by content.subject_present).",
                details={},
            )
        ]

    stripped = _strip_reply_prefix(subj)
    n = _count_words(stripped)
    details = {"words": n, "subject_after_prefix_strip": stripped}

    if n <= 3:
        return [
            Finding(
                check="copywriting.subject_word_count",
                severity=Severity.LOW,
                passed=False,
                message=(
                    f"Subject is {n} word(s) — too vague to drive opens. "
                    f"Aim for 6–10 words that name the specific topic or "
                    f"outcome."
                ),
                details=details,
            )
        ]

    if n <= 10:
        return [
            Finding(
                check="copywriting.subject_word_count",
                severity=Severity.INFO,
                passed=True,
                message=f"Subject word count {n} — within the 4–10 word target.",
                details=details,
            )
        ]

    if n <= 14:
        return [
            Finding(
                check="copywriting.subject_word_count",
                severity=Severity.MEDIUM,
                passed=False,
                message=(
                    f"Subject is {n} words — wordy and risks mobile "
                    f"truncation. Trim to 6–10 words; lead with the most "
                    f"specific noun."
                ),
                details=details,
            )
        ]

    return [
        Finding(
            check="copywriting.subject_word_count",
            severity=Severity.MEDIUM,
            passed=False,
            message=(
                f"Subject is {n} words — truncated on every mobile client. "
                f"Cut to 6–10 words."
            ),
            details=details,
        )
    ]
