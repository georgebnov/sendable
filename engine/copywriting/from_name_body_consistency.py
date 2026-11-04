"""From-name vs sign-off consistency.

Recipients expect the human in the From: line to also sign the body —
mismatches read as either spoofing or template churn ("Sent from <CRM>
on behalf of <some unrelated name>"). Filters score the inconsistency
as a low-effort bulk-mail marker.

Check: extract the From: display name, then look for it (or a
recognisable first-name / surname subset) inside the email's sign-off
region.

Sign-off region: every part of the closing that the extractor found.
  - `StructuredEmail.signature` — the isolated sign-off block.
  - P.S. block — sometimes the only place the sender names themself.
  - Footer — a company that signs with its name above its address has
    that whole paragraph peeled as the footer, because the address is a
    footer hint, so the name is only there.
  - Last 200 chars of the joined body text, when there is no signature.

Match precedence:
  - Full display-name substring (lowercased, whitespace-collapsed).
  - Any individual alphabetic word ≥3 chars from the display name —
     catches "Best, Jane" matching "Jane Doe".
  - Initials (first letters of each display-name word, ≥2 letters) as
     a word-boundary token — catches "— JD" signing for "Jane Doe".
     The footer does not count for this one.

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


def _sign_off_parts(structured) -> dict[str, str]:
    """The closing of the message, by the name of each part that it has."""
    body = "\n\n".join(structured.body_blocks).strip()
    parts = {
        "signature": structured.signature,
        "ps": structured.ps,
        "footer": structured.footer,
        "body_tail": None if structured.signature else body[-_REGION_TAIL:],
    }
    return {name: text for name, text in parts.items() if text}


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
                        "From display name is an unsubstituted merge tag: "
                        "no concrete name to match against sign-off."
                    ),
                    details=details,
                )
            ]

    structured = extract_structured(email)
    parts = _sign_off_parts(structured)
    region = "\n\n".join(parts.values())
    region_norm = _normalize(region)
    details["region_chars"] = len(region)
    details["region_source"] = "+".join(parts)

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

    # Initials fallback. Two letters are often an ordinary word, "no" for Nora Olsen,
    # and a footer is full of those. Only a person's closing signs with initials.
    init = _initials(tokens)
    signed_norm = _normalize("\n\n".join(t for name, t in parts.items() if name != "footer"))
    if init and re.search(rf"\b{re.escape(init)}\b", signed_norm):
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
