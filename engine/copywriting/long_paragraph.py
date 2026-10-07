"""Paragraph-length check.

A wall-of-text paragraph signals "I didn't edit" to the reader. They
skip it. Mobile clients exaggerate the problem — the same paragraph
that's 6 lines on desktop is 12+ on a phone.

Measure: per-paragraph word count from `StructuredEmail.body_blocks`
(P.S. included). Lines estimated at 12 words/line (a conservative
mobile-portrait approximation).

Bands (apply to the worst paragraph in the body):
  • ≤60 words  / ≤5 lines  → INFO PASS
  • 61–100 words / 6–8 lines → MEDIUM
  • >100 words  / >8 lines  → HIGH
"""

from __future__ import annotations

from ..parse import ParsedEmail
from ..report import Finding
from ..severity import Severity
from .extract import extract_structured

_WORDS_PER_LINE = 12
_MEDIUM_MIN_WORDS = 61
_HIGH_MIN_WORDS = 101


def _estimate_lines(words: int) -> int:
    return (words + _WORDS_PER_LINE - 1) // _WORDS_PER_LINE


async def run(email: ParsedEmail) -> list[Finding]:
    structured = extract_structured(email)
    paragraphs = list(structured.body_blocks)
    if structured.ps:
        paragraphs.append(structured.ps)

    if not paragraphs:
        return [
            Finding(
                check="copywriting.long_paragraph",
                severity=Severity.INFO,
                passed=True,
                message="No body paragraphs to measure.",
                details={},
            )
        ]

    sizes = [(p[:120], len(p.split()), _estimate_lines(len(p.split()))) for p in paragraphs]
    worst = max(sizes, key=lambda x: x[1])
    worst_preview, worst_words, worst_lines = worst

    details = {
        "worst_words": worst_words,
        "worst_lines_est": worst_lines,
        "worst_preview": worst_preview,
        "paragraph_count": len(paragraphs),
        "all_paragraph_word_counts": [w for _, w, _ in sizes],
    }

    if worst_words >= _HIGH_MIN_WORDS:
        return [
            Finding(
                check="copywriting.long_paragraph",
                severity=Severity.HIGH,
                passed=False,
                message=(
                    f"A paragraph is {worst_words} words / ~{worst_lines} "
                    f"lines. Readers scroll past walls of text — break it "
                    f"into shorter paragraphs, add a subhead, or convert "
                    f"to a list."
                ),
                details=details,
            )
        ]

    if worst_words >= _MEDIUM_MIN_WORDS:
        return [
            Finding(
                check="copywriting.long_paragraph",
                severity=Severity.MEDIUM,
                passed=False,
                message=(
                    f"A paragraph is {worst_words} words / ~{worst_lines} "
                    f"lines. Trim to ≤5 lines (~60 words) or split with a "
                    f"blank line / subhead."
                ),
                details=details,
            )
        ]

    return [
        Finding(
            check="copywriting.long_paragraph",
            severity=Severity.INFO,
            passed=True,
            message=(
                f"All paragraphs within length budget "
                f"(worst {worst_words} words / ~{worst_lines} lines)."
            ),
            details=details,
        )
    ]
