"""Personal-name From: display check.

Experian open-rate data: personal-name From: lines beat brand/team names
by 15–35%. Mechanism — recipient pattern-recognition. Personal-name
From: lines visually cluster with one-to-one mail; brand/team names
cluster with promo.

Check: parse From: into (display_name, address). Scan display name for
brokerage / team / corporate tokens (Realty, Group, Properties, LLC, …)
and for impersonal handle words (Info, Support, NoReply, …). Either hit
fires LOW advisory.

Placeholder handling: if the display name is *entirely* an unsubstituted
merge tag (e.g. `{{first_name}}`, `[FIRST NAME GOES HERE]`,
`*|FNAME|*`), inspect the tag contents. If the tag clearly references a
first-name field → PASS (personal-name slot, real first name will land
there at send time). If the tag references anything else → LOW advisory
(placeholder will inject a non-personal value).
"""

from __future__ import annotations

import re
from email.utils import parseaddr

from ..parse import ParsedEmail
from ..report import Finding
from ..severity import Severity

_FLAG_TOKENS = (
    "team",
    "realty",
    "group",
    "properties",
    "homes",
    "associates",
    "partners",
    "inc",
    "llc",
    "corp",
)
_FLAG_PHRASES = ("real estate",)
# `co.` carries a literal `.` so word-boundary handling needs a custom
# pattern — match `co.` followed by end-of-string or whitespace.
_CO_DOT_RX = re.compile(r"\bco\.(?=\s|$)", re.IGNORECASE)

_HANDLE_WORDS = frozenset(
    {
        "info",
        "hello",
        "contact",
        "support",
        "admin",
        "noreply",
        "no-reply",
    }
)

_PLACEHOLDER_RX = re.compile(
    r"\{\{[^}]+\}\}"  # {{first_name}}, Jinja / Handlebars
    r"|\{[^}]+\}"  # {first_name}
    r"|\[[^\]]+\]"  # [FIRST NAME GOES HERE], Campaign Monitor / Kit
    r"|%[A-Za-z_]+%"  # %FIRSTNAME%
    r"|\*\|[A-Za-z_]+\|\*",  # *|FNAME|*  Mailchimp
)

_FIRST_NAME_TAG_RX = re.compile(
    r"first[_\s-]?name|firstname|fname|f[_\s-]?name|fnameormember",
    re.IGNORECASE,
)


def _matches_token(display: str, token: str) -> bool:
    return re.search(rf"\b{re.escape(token)}\b", display, re.IGNORECASE) is not None


async def run(email: ParsedEmail) -> list[Finding]:
    raw_from = email.from_addr or ""
    display, addr = parseaddr(raw_from)
    display = (display or "").strip().strip('"').strip()
    details = {"display_name": display, "address": addr}

    # ── Placeholder branch ──────────────────────────────────────────
    if display:
        ph_matches = _PLACEHOLDER_RX.findall(display)
        residue = _PLACEHOLDER_RX.sub("", display).strip(" \t\n,-—–")
        if ph_matches and not residue:
            if any(_FIRST_NAME_TAG_RX.search(m) for m in ph_matches):
                return [
                    Finding(
                        check="copywriting.personal_from_name",
                        severity=Severity.INFO,
                        passed=True,
                        message=(
                            "From display name is a first-name merge tag — personal-name slot."
                        ),
                        details={**details, "placeholders": ph_matches},
                    )
                ]
            return [
                Finding(
                    check="copywriting.personal_from_name",
                    severity=Severity.LOW,
                    passed=False,
                    message=(
                        f"From display name is a placeholder but not a "
                        f"first-name field: {ph_matches[0]}. Personal-"
                        f"name From: lines outperform brand/team names by "
                        f"15% to 35% on open rate (Experian)."
                    ),
                    details={**details, "placeholders": ph_matches},
                )
            ]

    # ── Token scan ──────────────────────────────────────────────────
    hits: list[str] = []
    if display:
        for token in _FLAG_TOKENS:
            if _matches_token(display, token):
                hits.append(token)
        for phrase in _FLAG_PHRASES:
            if _matches_token(display, phrase):
                hits.append(phrase)
        if _CO_DOT_RX.search(display):
            hits.append("co.")
        if display.lower() in _HANDLE_WORDS:
            hits.append(f"handle:{display.lower()}")

    if hits:
        return [
            Finding(
                check="copywriting.personal_from_name",
                severity=Severity.LOW,
                passed=False,
                message=(
                    f"From display name reads as brand/team, not a person "
                    f"(matched: {', '.join(hits)}). Personal-name From: "
                    f"lines outperform brand/team From: lines by 15% to 35% on "
                    f"open rate (Experian)."
                ),
                details={**details, "matches": hits},
            )
        ]

    return [
        Finding(
            check="copywriting.personal_from_name",
            severity=Severity.INFO,
            passed=True,
            message=(
                f"From display name reads as personal: "
                f"{display or '(none — raw address shown to recipient)'}."
            ),
            details=details,
        )
    ]
