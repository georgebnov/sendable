"""From-name vs sign-off consistency.

Recipients expect the human in the From: line to also sign the body —
mismatches read as either spoofing or template churn ("Sent from <CRM>
on behalf of <some unrelated name>"). Filters score the inconsistency
as a low-effort bulk-mail marker.

Check: extract the From: display name, then look for it (or a
recognisable first-name / surname subset) inside the email's sign-off
region.

Sign-off region preference order:
  1. `StructuredEmail.signature` — the extractor's isolated sign-off
     block. Most reliable.
  2. P.S. block — sometimes the only place the sender names themself.
  3. Last 200 chars of the joined body text.

Match precedence:
  - Full display-name substring (lowercased, whitespace-collapsed).
  - Any individual alphabetic word ≥3 chars from the display name —
     catches "Best, Jane" matching "Jane Doe".
  - Initials (first letters of each display-name word, ≥2 letters) as
     a word-boundary token — catches "— JD" signing for "Jane Doe".

Skips (INFO PASS):
  - No display name at all (raw address only).
  - Display name is entirely an unsubstituted merge tag.
"""

from __future__ import annotations

import re
from email.utils import parseaddr

from ..parse import ParsedEmail
from ..report import Finding
from ..severity import Severity
from .extract import extract_structured

_PLACEHOLDER_RX = re.compile(
    r"\{\{[^}]+\}\}|\{[^}]+\}|\[[^\]]+\]|%[A-Za-z_]+%|\*\|[A-Za-z_]+\|\*",
)
_WORD_RX = re.compile(r"[A-Za-z]{3,}")
# Common honorifics / suffixes that aren't usable for identity match.
_NAME_STOPWORDS = frozenset(
    {
        "mr",
        "mrs",
        "ms",
        "dr",
        "prof",
        "the",
        "and",
        "team",
    }
)

_REGION_TAIL = 200


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def _sign_off_region(structured) -> str:
    if structured.signature:
        return structured.signature
    if structured.ps:
        return structured.ps
    body = "\n\n".join(structured.body_blocks).strip()
    return body[-_REGION_TAIL:] if body else ""


def _name_tokens(display: str) -> list[str]:
    return [t.lower() for t in _WORD_RX.findall(display) if t.lower() not in _NAME_STOPWORDS]


def _initials(tokens: list[str]) -> str:
    return "".join(t[0] for t in tokens) if len(tokens) >= 2 else ""


async def run(email: ParsedEmail) -> list[Finding]:
    display, _ = parseaddr(email.from_addr or "")
    display = (display or "").strip().strip('"').strip()
    details: dict = {"display_name": display}

    if not display:
        return [
            Finding(
                check="copywriting.from_name_body_consistency",
                severity=Severity.INFO,
                passed=True,
                message="No From display name to verify against sign-off.",
                details=details,
            )
        ]

    # Skip if display name is purely a placeholder.
    if _PLACEHOLDER_RX.search(display):
        residue = _PLACEHOLDER_RX.sub("", display).strip(" \t\n,-—–")
        if not residue:
            return [
                Finding(
                    check="copywriting.from_name_body_consistency",
                    severity=Severity.INFO,
                    passed=True,
                    message=(
                        "From display name is an unsubstituted merge tag — "
                        "no concrete name to match against sign-off."
                    ),
                    details=details,
                )
            ]

    structured = extract_structured(email)
    region = _sign_off_region(structured)
    region_norm = _normalize(region)
    details["region_chars"] = len(region)
    details["region_source"] = (
        "signature" if structured.signature else "ps" if structured.ps else "body_tail"
    )

    if not region_norm:
        return [
            Finding(
                check="copywriting.from_name_body_consistency",
                severity=Severity.INFO,
                passed=True,
                message="No body sign-off region to inspect.",
                details=details,
            )
        ]

    display_norm = _normalize(display)

    # Full-display-name substring.
    if display_norm and display_norm in region_norm:
        return [
            Finding(
                check="copywriting.from_name_body_consistency",
                severity=Severity.INFO,
                passed=True,
                message=f'From name "{display}" appears in sign-off.',
                details={**details, "match_kind": "full"},
            )
        ]

    tokens = _name_tokens(display)
    # Any individual alphabetic name word ≥3 chars.
    word_hits = [t for t in tokens if re.search(rf"\b{re.escape(t)}\b", region_norm)]
    if word_hits:
        return [
            Finding(
                check="copywriting.from_name_body_consistency",
                severity=Severity.INFO,
                passed=True,
                message=(f"From name partial match in sign-off: {', '.join(word_hits)}."),
                details={**details, "match_kind": "partial", "tokens": word_hits},
            )
        ]

    # Initials fallback.
    init = _initials(tokens)
    if init and re.search(rf"\b{re.escape(init)}\b", region_norm):
        return [
            Finding(
                check="copywriting.from_name_body_consistency",
                severity=Severity.INFO,
                passed=True,
                message=f'From-name initials "{init.upper()}" appear in sign-off.',
                details={**details, "match_kind": "initials", "initials": init},
            )
        ]

    return [
        Finding(
            check="copywriting.from_name_body_consistency",
            severity=Severity.MEDIUM,
            passed=False,
            message=(
                f'From display name "{display}" does not appear in the '
                f"sign-off region. Recipients (and filters) expect the "
                f"sender in From: to also sign the body."
            ),
            details={**details, "tokens_tried": tokens},
        )
    ]
