"""Preheader vs subject token-overlap check.

The preheader is a *second* impression — visible next to the subject in
every modern inbox UI. Repeating the subject line wastes that real
estate. The reader has already read the subject; making the preheader
say the same thing means the email occupies two preview-text slots with
the same information instead of one + one.

Measure: token-overlap ratio.
    overlap = |preheader_tokens ∩ subject_tokens| / |subject_tokens|

Tokens: lowercased alphanumeric runs from the subject line and from the
first 100 chars of the preheader. Bare punctuation skipped.

Bands:
  • <60% overlap     → INFO PASS
  • ≥60% overlap     → LOW advisory (wasted second impression)
"""

from __future__ import annotations

import re

from ..parse import ParsedEmail
from ..report import Finding
from ..severity import Severity
from .extract import extract_structured

_TOKEN_RX = re.compile(r"[a-z0-9]+")
_PREHEADER_WINDOW = 100
_OVERLAP_THRESHOLD = 0.60


def _tokens(text: str) -> set[str]:
    return set(_TOKEN_RX.findall((text or "").lower()))


async def run(email: ParsedEmail) -> list[Finding]:
    structured = extract_structured(email)
    subject = (structured.subject or "").strip()
    preheader = (structured.preview_text or "").strip()

    if not subject or not preheader:
        return [
            Finding(
                check="copywriting.preheader_repeats_subject",
                severity=Severity.INFO,
                passed=True,
                message=(
                    "Skipped — need both subject and preheader to compare."
                ),
                details={
                    "subject_present": bool(subject),
                    "preheader_present": bool(preheader),
                },
            )
        ]

    subj_tokens = _tokens(subject)
    pre_window = preheader[:_PREHEADER_WINDOW]
    pre_tokens = _tokens(pre_window)

    if not subj_tokens:
        return [
            Finding(
                check="copywriting.preheader_repeats_subject",
                severity=Severity.INFO,
                passed=True,
                message="Subject has no comparable tokens.",
                details={"subject": subject, "preheader": pre_window},
            )
        ]

    overlap = len(subj_tokens & pre_tokens) / len(subj_tokens)
    overlap_pct = round(overlap * 100, 1)
    details = {
        "overlap_ratio": round(overlap, 3),
        "overlap_pct": overlap_pct,
        "shared_tokens": sorted(subj_tokens & pre_tokens),
        "subject": subject,
        "preheader": pre_window,
    }

    if overlap >= _OVERLAP_THRESHOLD:
        return [
            Finding(
                check="copywriting.preheader_repeats_subject",
                severity=Severity.LOW,
                passed=False,
                message=(
                    f"Preheader repeats {overlap_pct}% of subject tokens — "
                    f"wasted second impression. Use the preheader to add "
                    f"detail, urgency, or curiosity the subject couldn't fit."
                ),
                details=details,
            )
        ]

    return [
        Finding(
            check="copywriting.preheader_repeats_subject",
            severity=Severity.INFO,
            passed=True,
            message=f"Preheader adds new content ({overlap_pct}% token overlap).",
            details=details,
        )
    ]
