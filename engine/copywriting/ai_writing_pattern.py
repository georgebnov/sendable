"""AI-generated-copy detection: two deterministic signals.

Signal 1 — phrase fingerprint. LLM training optimises for politeness
and hedging, producing a recurrent vocabulary that human marketers
rarely write at the same density ("delve into", "navigate the",
"elevate your", "feel free to reach out", "it's worth noting", …).

Signal 2 — sentence-length burstiness. Human writers vary sentence
length sharply (a fragment, then a long compound thought). LLM output
clusters around a target length, so the standard deviation of per-
sentence word counts stays low. We only apply this signal once the
sample is ≥8 sentences — below that, SD is too noisy to act on.

Tier logic:
  • ≤1 phrase + (variance OK or N<8)         → INFO PASS
  • exactly 2 phrases, variance OK            → MEDIUM (phrase only)
  • ≤1 phrase, low SD                         → MEDIUM (variance only)
  • ≥3 phrases                                → HIGH
  • ≥2 phrases AND low SD                     → HIGH (both)
"""

from __future__ import annotations

import re
import statistics

from ..parse import ParsedEmail
from ..report import Finding
from ..severity import Severity
from .extract import extract_structured

_PHRASE_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("in conclusion", re.compile(r"\bin\s+conclusion\b", re.IGNORECASE)),
    (
        "it's worth noting",
        re.compile(r"\bit'?s\s+worth\s+noting\b|\bit\s+is\s+worth\s+noting\b", re.IGNORECASE),
    ),
    ("feel free to reach out", re.compile(r"\bfeel\s+free\s+to\s+reach\s+out\b", re.IGNORECASE)),
    (
        "don't hesitate to contact",
        re.compile(
            r"\bdon'?t\s+hesitate\s+to\s+contact\b|\bdo\s+not\s+hesitate\s+to\s+contact\b",
            re.IGNORECASE,
        ),
    ),
    ("delve into", re.compile(r"\bdelve\s+into\b", re.IGNORECASE)),
    (
        "leverage (verb)",
        re.compile(r"\bleverage\s+(?:the|your|our|my|a|an|this|that|these|those)\b", re.IGNORECASE),
    ),
    ("in today's market", re.compile(r"\bin\s+today'?s\s+\w+", re.IGNORECASE)),
    (
        "as a [profession] i understand",
        re.compile(r"\bas\s+an?\s+(?:\w+\s+){0,3}\w+\s*,?\s+i\s+understand\b", re.IGNORECASE),
    ),
    (
        "i wanted to take a moment",
        re.compile(r"\bi\s+wanted\s+to\s+take\s+a\s+moment\b", re.IGNORECASE),
    ),
    ("navigate the", re.compile(r"\bnavigate\s+the\b", re.IGNORECASE)),
    ("elevate your", re.compile(r"\belevate\s+your\b", re.IGNORECASE)),
    ("at the end of the day", re.compile(r"\bat\s+the\s+end\s+of\s+the\s+day\b", re.IGNORECASE)),
    (
        "it is important to note",
        re.compile(
            r"\bit\s+is\s+important\s+to\s+note\b|\bit'?s\s+important\s+to\s+note\b", re.IGNORECASE
        ),
    ),
    ("in summary", re.compile(r"\bin\s+summary\b", re.IGNORECASE)),
    ("to summarize", re.compile(r"\bto\s+summari[sz]e\b", re.IGNORECASE)),
)

_SENTENCE_SPLIT_RX = re.compile(r"[.!?]+")
_WORD_RX = re.compile(r"[A-Za-z]+(?:'[A-Za-z]+)?")

_MIN_SENTENCES_FOR_VARIANCE = 8
_SD_THRESHOLD = 3.5


def _scan_phrases(text: str) -> list[str]:
    hits: list[str] = []
    for label, rx in _PHRASE_PATTERNS:
        if rx.search(text):
            hits.append(label)
    return hits


def _sentence_lengths(text: str) -> list[int]:
    raw = [s.strip() for s in _SENTENCE_SPLIT_RX.split(text) if s.strip()]
    lengths: list[int] = []
    for s in raw:
        n = len(_WORD_RX.findall(s))
        if n > 0:
            lengths.append(n)
    return lengths


async def run(email: ParsedEmail) -> list[Finding]:
    structured = extract_structured(email)
    body = "\n\n".join(structured.body_blocks)
    if structured.ps:
        body = body + "\n\n" + structured.ps

    phrase_hits = _scan_phrases(body)
    phrase_count = len(phrase_hits)

    lengths = _sentence_lengths(body)
    n_sentences = len(lengths)
    sd: float | None = None
    variance_applicable = n_sentences >= _MIN_SENTENCES_FOR_VARIANCE
    if variance_applicable:
        sd = round(statistics.stdev(lengths), 2)
    low_variance = bool(variance_applicable and sd is not None and sd < _SD_THRESHOLD)
    phrase_signal = phrase_count >= 2

    details = {
        "phrase_hits": phrase_hits,
        "phrase_count": phrase_count,
        "n_sentences": n_sentences,
        "sentence_sd": sd,
        "variance_applicable": variance_applicable,
        "low_variance": low_variance,
        "sd_threshold": _SD_THRESHOLD,
    }

    # HIGH branch.
    if phrase_count >= 3 or (phrase_signal and low_variance):
        reasons = []
        if phrase_count >= 3:
            reasons.append(f"{phrase_count} AI-pattern phrases")
        if phrase_signal and low_variance:
            reasons.append(
                f"low sentence-length SD ({sd} < {_SD_THRESHOLD}) paired with phrase fingerprint"
            )
        return [
            Finding(
                check="copywriting.ai_writing_pattern",
                severity=Severity.HIGH,
                passed=False,
                message=(
                    f"Multiple AI-output signals firing: {'; '.join(reasons)}. "
                    f"Recipients (and increasingly filters) classify "
                    f"high-density AI text as low-effort."
                ),
                details=details,
            )
        ]

    # MEDIUM branch — single signal.
    if phrase_count == 2 or (phrase_count <= 1 and low_variance):
        if phrase_count == 2:
            msg = (
                "Two AI-pattern phrases detected — borderline. Replace "
                f"{', '.join(phrase_hits)} with your natural phrasing."
            )
        else:
            msg = (
                f"Sentence length variance is low (SD {sd} < {_SD_THRESHOLD}) — "
                f"reads as machine-paced. Mix short fragments with longer "
                f"compound sentences."
            )
        return [
            Finding(
                check="copywriting.ai_writing_pattern",
                severity=Severity.MEDIUM,
                passed=False,
                message=msg,
                details=details,
            )
        ]

    msg = "No AI-pattern signals firing."
    if phrase_count == 1:
        msg = f"One AI-pattern phrase ({phrase_hits[0]}) — within tolerance."
    return [
        Finding(
            check="copywriting.ai_writing_pattern",
            severity=Severity.INFO,
            passed=True,
            message=msg,
            details=details,
        )
    ]
