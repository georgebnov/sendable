"""Primary-CTA outcome-copy check.

David's rule: the button copy should name the imagined best state, not
the mechanical action. "Move into your dream home" beats "Buy Now."
A generic action-verb button shifts the reader's frame from outcome
("what I get") to transaction ("what I do") — measurably worse CTR.

Primary CTA selection: first button-styled anchor in document order;
fallback to first action-verb anchor. Passive nav (unsubscribe / view
in browser) is excluded — same denylist as `copywriting.cta_count`.

Match: normalize CTA text (lowercase, strip punctuation, collapse
whitespace), then exact-equal one of the bad phrases OR bad phrase
followed by an intensifier ("now" / "today" / "here" / "below"). This
catches "Buy Now", "Click Here!", "Get Started Today" while sparing
fully-rewritten button copy that happens to contain a flagged word
("Next steps after viewing" — not flagged).
"""

from __future__ import annotations

import re

from ..parse import ParsedEmail
from ..report import Finding
from ..severity import Severity
from .cta_count import _is_passive
from .extract import extract_structured

_BAD_PATTERNS = (
    "buy now",
    "click here",
    "submit",
    "learn more",
    "read more",
    "get started",
    "sign up",
    "register",
    "continue",
    "proceed",
    "find out more",
    "go",
    "next",
)

_TAIL_INTENSIFIERS = ("now", "today", "here", "below")


def _normalize(text: str) -> str:
    t = (text or "").lower().strip()
    t = re.sub(r"[^\w\s]+", " ", t)
    return re.sub(r"\s+", " ", t).strip()


def _matched_bad_phrase(text: str) -> str | None:
    norm = _normalize(text)
    if not norm:
        return None
    for phrase in _BAD_PATTERNS:
        if norm == phrase:
            return phrase
        for tail in _TAIL_INTENSIFIERS:
            if norm == f"{phrase} {tail}":
                return phrase
    return None


async def run(email: ParsedEmail) -> list[Finding]:
    structured = extract_structured(email)
    active = [c for c in structured.cta_blocks if not _is_passive(c.text, c.href)]

    if not active:
        return [
            Finding(
                check="copywriting.cta_outcome_copy",
                severity=Severity.INFO,
                passed=True,
                message="No active CTA detected — nothing to grade.",
                details={},
            )
        ]

    # Primary = first button-styled; fallback to first overall.
    primary = next((c for c in active if c.has_button_styling), active[0])

    matched = _matched_bad_phrase(primary.text)
    if matched:
        return [
            Finding(
                check="copywriting.cta_outcome_copy",
                severity=Severity.MEDIUM,
                passed=False,
                message=(
                    f'Primary CTA reads "{primary.text}" — generic action '
                    f'verb ("{matched}"). Rewrite to name the outcome the '
                    f'reader gets, not the mechanical action. e.g. "Move '
                    f'into your dream home" not "Buy Now".'
                ),
                details={
                    "primary_cta_text": primary.text,
                    "matched_pattern": matched,
                    "href": primary.href[:120],
                },
            )
        ]

    return [
        Finding(
            check="copywriting.cta_outcome_copy",
            severity=Severity.INFO,
            passed=True,
            message=(f'Primary CTA "{primary.text}" avoids generic action-verb patterns.'),
            details={
                "primary_cta_text": primary.text,
                "href": primary.href[:120],
            },
        )
    ]
