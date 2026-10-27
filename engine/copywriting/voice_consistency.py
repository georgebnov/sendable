"""Voice-consistency check: I-voice vs We-voice mixing.

David's rule: pick one — agent (I / my / me) or brand (we / our / us) —
and stay in it. Mixed voice signals either careless authoring or a
template grafted onto a personal email. Readers parse it as
inconsistent identity; filters notice nothing, but conversion drops.

Tokens:
  I-voice  → I, my, me, I'm, I've, I'll, I'd
  We-voice → we, our, us, we're, we've, we'll, we'd

Rule: dominant_share = max(i, we) / (i + we). ≥80% → consistent.
60–79% → LOW advisory (mixed). <60% → also LOW (heavier mix).

Minimum sample: 4 total voice tokens. Below that, share math is too
sensitive to a single occurrence — short replies and confirmations
shouldn't trip the rule.
"""

from __future__ import annotations

import re

from ..parse import ParsedEmail
from ..report import Finding
from ..severity import Severity
from .extract import extract_structured

_I_VOICE_RX = re.compile(
    r"\b(?:i|my|me|i'm|i've|i'll|i'd)\b",
    re.IGNORECASE,
)
_WE_VOICE_RX = re.compile(
    r"\b(?:we|our|us|we're|we've|we'll|we'd)\b",
    re.IGNORECASE,
)

_MIN_TOTAL_TOKENS = 4
_CONSISTENT_THRESHOLD = 0.80


async def run(email: ParsedEmail) -> list[Finding]:
    structured = extract_structured(email)
    parts = list(structured.body_blocks)
    if structured.ps:
        parts.append(structured.ps)
    body = "\n\n".join(parts)

    i_hits = _I_VOICE_RX.findall(body)
    we_hits = _WE_VOICE_RX.findall(body)
    i_count = len(i_hits)
    we_count = len(we_hits)
    total = i_count + we_count

    details: dict[str, object] = {
        "i_count": i_count,
        "we_count": we_count,
        "total": total,
        "threshold_pct": int(_CONSISTENT_THRESHOLD * 100),
        "min_total": _MIN_TOTAL_TOKENS,
    }

    if total < _MIN_TOTAL_TOKENS:
        return [
            Finding(
                check="copywriting.voice_consistency",
                severity=Severity.INFO,
                passed=True,
                message=(f"Only {total} voice token(s): too few to grade voice consistency."),
                details=details,
            )
        ]

    dominant = max(i_count, we_count) / total
    details["dominant_share_pct"] = round(dominant * 100, 1)
    dominant_voice = "I" if i_count >= we_count else "We"
    details["dominant_voice"] = dominant_voice

    if dominant >= _CONSISTENT_THRESHOLD:
        return [
            Finding(
                check="copywriting.voice_consistency",
                severity=Severity.INFO,
                passed=True,
                message=(
                    f"Voice consistent: {dominant_voice}-voice carries "
                    f"{details['dominant_share_pct']}% of voice tokens."
                ),
                details=details,
            )
        ]

    return [
        Finding(
            check="copywriting.voice_consistency",
            severity=Severity.LOW,
            passed=False,
            message=(
                f"Voice split detected. I-voice {i_count} / We-voice "
                f"{we_count} (dominant {details['dominant_share_pct']}% < "
                f"{details['threshold_pct']}%). Pick agent (I/my/me) or "
                f"brand (we/our/us) and stay in it."
            ),
            details=details,
        )
    ]
