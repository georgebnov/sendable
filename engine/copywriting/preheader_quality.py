"""Preheader / preview-text quality check.

The preheader is the second-line preview most inbox UIs show next to
the subject. When a marketer doesn't author one, mail clients fall back
to the first visible content of the body — which is usually template
chrome ("View in browser", "Having trouble seeing this?", an
unsubscribe link, etc.). Filters and humans both read that as a low-
effort bulk send.

Sources for the preview text, in preference order:
  1. `StructuredEmail.preview_text` — hidden-styled preheader element
     in the HTML head, the industry convention.
  2. Lead of body content used as a fallback approximation when no
     hidden preheader element exists — what the inbox will actually
     show, even though the marketer didn't intentionally set it.

FAIL conditions (HIGH):
  - Preheader entirely absent / empty.
  - Preheader under 20 chars (insufficient signal).
  - Preheader contains an artifact pattern from a template fallback
    string ("view in browser", "having trouble", "can't see this",
    "click here to view", or "unsubscribe" appearing in the first 30
    chars — i.e. as the opening of the preview).
"""

from __future__ import annotations

import re

from ..parse import ParsedEmail
from ..report import Finding
from ..severity import Severity
from .extract import extract_structured

_ARTIFACT_SUBSTRINGS = (
    "view in browser",
    "having trouble",
    "can't see this",
    "cant see this",
    "click here to view",
)

_OPENING_WINDOW = 30
_MIN_CHARS = 20


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip().lower())


async def run(email: ParsedEmail) -> list[Finding]:
    structured = extract_structured(email)
    preview = (structured.preview_text or "").strip()
    norm = _normalize(preview)

    if not preview:
        return [
            Finding(
                check="copywriting.preheader_quality",
                severity=Severity.HIGH,
                passed=False,
                message=(
                    "No preheader / preview text detected. Inbox preview "
                    "will fall back to whatever the body opens with — "
                    "usually template chrome. Add a hidden preheader to "
                    "control the second-line message."
                ),
                details={"preview": None},
            )
        ]

    if len(preview) < _MIN_CHARS:
        return [
            Finding(
                check="copywriting.preheader_quality",
                severity=Severity.HIGH,
                passed=False,
                message=(
                    f"Preheader is only {len(preview)} chars — insufficient "
                    f"signal. Target ≥{_MIN_CHARS} chars of intentional copy."
                ),
                details={"preview": preview, "chars": len(preview)},
            )
        ]

    hits = [s for s in _ARTIFACT_SUBSTRINGS if s in norm]
    if "unsubscribe" in norm[:_OPENING_WINDOW]:
        hits.append("unsubscribe-opening")

    if hits:
        return [
            Finding(
                check="copywriting.preheader_quality",
                severity=Severity.HIGH,
                passed=False,
                message=(
                    f"Preheader is a template artifact (matched: "
                    f"{', '.join(hits)}). The marketer didn't author the "
                    f"preview — the inbox is showing fallback chrome."
                ),
                details={"preview": preview, "matches": hits},
            )
        ]

    return [
        Finding(
            check="copywriting.preheader_quality",
            severity=Severity.INFO,
            passed=True,
            message=f"Preheader present ({len(preview)} chars), no artifacts.",
            details={"preview": preview, "chars": len(preview)},
        )
    ]
