"""Flesch-Kincaid Grade Level check on body narrative.

Formula: 0.39 × (words/sentences) + 11.8 × (syllables/words) − 15.59.

Bands (research-backed: USA Today ≈ grade 8, NYT ≈ grade 10, academic
papers ≈ grade 14+):
  • Grade 6–9   → INFO PASS  (conversational, ideal for cold/newsletter)
  • Grade 10–12 → MEDIUM     (formal, reads legalistic to skimmers)
  • Grade 13+   → HIGH       (academic; readers bounce before the CTA)

We grade the *narrative body only* — `StructuredEmail.body_blocks` joined,
P.S. included. Greeting, signature, footer, section headers, CTAs, and
preview text are excluded so we measure how the marketer is writing,
not boilerplate that always reads the same.

Sample-size guard: below 30 words or 3 sentences the FK estimate is too
noisy to act on, so we emit a single INFO PASS noting the skip.

Syllable counting is the stdlib vowel-cluster heuristic — adjacent
vowels collapse to one syllable, silent trailing 'e' is subtracted
(except '-le' / '-les' endings), one syllable floor per word.
Empirically ~5-10% off CMU Pronouncing Dictionary on individual words
but well within the precision needed for grade-level binning.
"""

from __future__ import annotations

import re

from ..parse import ParsedEmail
from ..report import Finding
from ..severity import Severity
from .extract import extract_structured

_VOWELS = "aeiouy"
_WORD_RX = re.compile(r"[A-Za-z]+(?:'[A-Za-z]+)?")
_SENTENCE_RX = re.compile(r"[.!?]+(?:\s|$)")

_MIN_WORDS = 30
_MIN_SENTENCES = 3

_GRADE_OK_MAX = 9      # ≤9 → INFO
_GRADE_MED_MAX = 12    # 10-12 → MEDIUM
                       # ≥13 → HIGH


def _count_syllables(word: str) -> int:
    """Vowel-cluster heuristic. Returns at least 1 for any alphabetic word."""
    w = word.lower()
    if not w:
        return 0
    count = 0
    prev_vowel = False
    for ch in w:
        is_vowel = ch in _VOWELS
        if is_vowel and not prev_vowel:
            count += 1
        prev_vowel = is_vowel
    # Silent trailing 'e' — but keep it for '-le' / '-les' (table, candles).
    if w.endswith("e") and not w.endswith(("le", "les")) and count > 1:
        count -= 1
    return max(1, count)


def _narrative_body(structured) -> str:
    parts = [*structured.body_blocks]
    if structured.ps:
        parts.append(structured.ps)
    return "\n\n".join(parts)


def _flesch_kincaid_grade(text: str) -> tuple[float | None, dict]:
    """Return (grade, stats). grade is None when the sample is too small."""
    words = _WORD_RX.findall(text)
    n_words = len(words)
    n_sentences = len([s for s in _SENTENCE_RX.split(text) if s.strip()])
    # `re.split` returns the inter-delimiter chunks; count delimiters as
    # sentence terminators instead, more robust on missing trailing
    # punctuation.
    n_sentences = max(n_sentences, len(_SENTENCE_RX.findall(text)))

    stats = {
        "words": n_words,
        "sentences": n_sentences,
        "min_words": _MIN_WORDS,
        "min_sentences": _MIN_SENTENCES,
    }
    if n_words < _MIN_WORDS or n_sentences < _MIN_SENTENCES:
        return None, stats

    syllables = sum(_count_syllables(w) for w in words)
    stats["syllables"] = syllables
    grade = (
        0.39 * (n_words / n_sentences)
        + 11.8 * (syllables / n_words)
        - 15.59
    )
    return round(grade, 1), stats


async def run(email: ParsedEmail) -> list[Finding]:
    structured = extract_structured(email)
    body = _narrative_body(structured)

    grade, stats = _flesch_kincaid_grade(body)

    if grade is None:
        return [
            Finding(
                check="copywriting.reading_level",
                severity=Severity.INFO,
                passed=True,
                message=(
                    f"Body too short for a reliable reading-level grade "
                    f"({stats['words']} words, {stats['sentences']} sentences; "
                    f"need ≥{_MIN_WORDS} words and ≥{_MIN_SENTENCES} sentences)."
                ),
                details=stats,
            )
        ]

    stats["grade"] = grade

    if grade <= _GRADE_OK_MAX:
        return [
            Finding(
                check="copywriting.reading_level",
                severity=Severity.INFO,
                passed=True,
                message=(
                    f"Reading level Grade {grade} — conversational range "
                    f"(USA Today to NYT)."
                ),
                details=stats,
            )
        ]

    if grade <= _GRADE_MED_MAX:
        return [
            Finding(
                check="copywriting.reading_level",
                severity=Severity.MEDIUM,
                passed=False,
                message=(
                    f"Reading level Grade {grade} — formal range, risks "
                    f"reading like a legal document. Aim for Grade 6–9: "
                    f"shorter sentences, plainer words."
                ),
                details=stats,
            )
        ]

    return [
        Finding(
            check="copywriting.reading_level",
            severity=Severity.HIGH,
            passed=False,
            message=(
                f"Reading level Grade {grade} — academic range. Audience "
                f"disengages before the CTA. Cut sentence length and "
                f"replace multi-syllable words with everyday ones."
            ),
            details=stats,
        )
    ]
