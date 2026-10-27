"""CTA-count check: competing-attention deliverability + conversion signal.

Marketing copy research (StoryBrand, Made to Stick, every modern
email-conversion deck) converges on a single rule: one primary CTA per
email. Each additional CTA dilutes the click signal and gives the reader
a parallel "do nothing" path. Spam filters also weight high CTA-density
relative to body length when scoring promotional intent.

Source: `StructuredEmail.cta_blocks` — anchors whose visible text matches
an action verb pattern OR whose inline style declares button shape
(background + padding/border-radius). De-duplicated on (text, href).

Passive navigational anchors (unsubscribe, view-in-browser, manage
preferences) are filtered out before counting — they're chrome, not
asks. They can still slip into `cta_blocks` when the ESP styles them
as buttons.

Bands:
  • 0–1 CTA  → INFO PASS  (focused ask)
  • 2 CTAs   → MEDIUM      (competing attention)
  • 3+ CTAs  → HIGH        (scattershot; reads as bulk promo)
"""

from __future__ import annotations

import re

from ..parse import ParsedEmail
from ..report import Finding
from ..severity import Severity
from .extract import extract_structured

# Anchor visible text patterns that mark passive nav, not an ask.
_PASSIVE_TEXT_RX = re.compile(
    r"\bunsubscribe\b"
    r"|\bopt[\s-]?out\b"
    r"|\bview\s+(?:in|this)\s+(?:browser|email|web)\b"
    r"|\bweb\s+version\b"
    r"|\bemail\s+preferences\b"
    r"|\b(?:manage|update)\s+(?:your\s+)?(?:preferences|subscription)\b"
    r"|\bprivacy\s+policy\b"
    r"|\bterms\s+of\s+(?:use|service)\b"
    r"|\bcontact\s+us\b",
    re.IGNORECASE,
)

# Hrefs that point at chrome endpoints — ESP unsub / browser-view URLs
# often include these path tokens.
_PASSIVE_HREF_RX = re.compile(
    r"unsubscribe|/unsub/|/optout|view[-_]?in[-_]?browser|webversion|"
    r"manage[-_]?preferences|email[-_]?preferences",
    re.IGNORECASE,
)


def _is_passive(text: str, href: str) -> bool:
    if _PASSIVE_TEXT_RX.search(text or ""):
        return True
    return bool(_PASSIVE_HREF_RX.search(href or ""))


async def run(email: ParsedEmail) -> list[Finding]:
    structured = extract_structured(email)

    active = [c for c in structured.cta_blocks if not _is_passive(c.text, c.href)]
    count = len(active)
    samples = [{"text": c.text[:80], "href": c.href[:120]} for c in active[:10]]

    if count <= 1:
        return [
            Finding(
                check="copywriting.cta_count",
                severity=Severity.INFO,
                passed=True,
                message=f"{count} active CTA detected: focused ask.",
                details={"count": count, "ctas": samples},
            )
        ]

    if count == 2:
        return [
            Finding(
                check="copywriting.cta_count",
                severity=Severity.MEDIUM,
                passed=False,
                message=(
                    "2 active CTAs detected: competing attention. Pick the "
                    "single most important next step; demote the other to "
                    "an inline link or drop it."
                ),
                details={"count": count, "ctas": samples},
            )
        ]

    return [
        Finding(
            check="copywriting.cta_count",
            severity=Severity.HIGH,
            passed=False,
            message=(
                f"{count} active CTAs detected: scattershot. Multiple "
                f"button-shaped asks read as bulk promo to filters and "
                f"dilute conversion. Collapse to one primary CTA."
            ),
            details={"count": count, "ctas": samples},
        )
    ]
