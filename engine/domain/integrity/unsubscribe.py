"""Unsubscribe-related checks: RFC 8058 headers, visible in-body link,
and clip-risk when the unsub anchor sits below Gmail's 102KB threshold.

Gmail (Feb 2024), Yahoo (Feb 2024), and Microsoft (May 2025) now bulk-reject
mail without RFC 8058 one-click unsubscribe. Missing headers on bulk mail
is effectively a hard-deliverability failure.

Bulk-mail is inferred from any of: List-ID, Feedback-ID, common ESP
campaign-id headers, or Precedence: bulk. A non-bulk 1:1 email doesn't
need List-Unsubscribe, so severity degrades to INFO in that case.

Also emits a `headers.precedence_bulk` advisory: when the message
clearly looks bulk (List-ID etc.) but `Precedence: bulk` is absent.
SpamAssassin's MISSING_MID-style rules give a small negative weight
for bulk-shaped mail that doesn't declare itself. Minor signal, easy
to publish, LOW severity.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup

from ...parse import ParsedEmail
from ...report import Finding
from ...severity import Severity

_BULK_HEADERS = (
    "list-id",
    "feedback-id",
    "x-mailchimp-campaign-id",
    "x-campaign",
    "x-campaign-id",
    "x-klaviyo-messageid",
    "x-ac-campaign-id",
)

# Visible-link signals for body unsubscribe. Matches "Unsubscribe", "opt out",
# "email preferences", and common href substrings ESPs use. Case-insensitive.
_UNSUB_TEXT_RX = re.compile(r"\b(unsubscribe|opt[- ]?out|email\s+preferences)\b", re.IGNORECASE)
_UNSUB_HREF_RX = re.compile(
    r"(unsubscribe|optout|opt[-_]out|email[-_]?preferences|email[-_]?settings|remove[-_]?me)",
    re.IGNORECASE,
)

# RFC 8058: List-Unsubscribe-Post header value must include this token.
_ONE_CLICK_RX = re.compile(r"List-Unsubscribe\s*=\s*One-Click", re.IGNORECASE)

GMAIL_CLIP_BYTES = 102_000


def _is_bulk(email: ParsedEmail) -> bool:
    for h in _BULK_HEADERS:
        if email.headers.get(h):
            return True
    precedence = email.headers.get("precedence", [])
    return bool(any(v.strip().lower() == "bulk" for v in precedence))


def _find_unsub_anchor(soup: BeautifulSoup):
    """Return the first <a> element whose visible text or href looks like an
    unsubscribe link. Returns None if none found."""
    for a in soup.find_all("a"):
        href = a.get("href") or ""
        text = a.get_text(separator=" ", strip=True)
        if _UNSUB_TEXT_RX.search(text) or _UNSUB_HREF_RX.search(href):
            return a
    return None


def _byte_offset_of_anchor(html: str, anchor_str: str) -> int | None:
    """Approximate byte-offset of an anchor element in the HTML by searching
    for a substring representation of it. Returns None if not locatable."""
    # Use a short distinctive slice of the anchor's rendered HTML tag.
    needle = anchor_str[:120]
    if not needle:
        return None
    idx = html.find(needle)
    if idx < 0:
        return None
    return len(html[:idx].encode("utf-8"))


async def run(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    bulk = _is_bulk(email)

    # `Precedence: bulk` advisory. Only meaningful when the message looks
    # bulk via other signals (List-ID / Feedback-ID / campaign-id). If
    # detection only fired via `precedence: bulk` itself, this check is
    # redundant — skip in that case to avoid a tautology.
    precedence_values = [v.strip().lower() for v in email.headers.get("precedence", [])]
    has_precedence_bulk = "bulk" in precedence_values
    bulk_via_other_signal = any(email.headers.get(h) for h in _BULK_HEADERS)
    if bulk_via_other_signal:
        if has_precedence_bulk:
            findings.append(
                Finding(
                    check="headers.precedence_bulk",
                    severity=Severity.INFO,
                    passed=True,
                    message="Precedence: bulk header present.",
                )
            )
        else:
            findings.append(
                Finding(
                    check="headers.precedence_bulk",
                    severity=Severity.LOW,
                    passed=False,
                    message=(
                        "Bulk-shaped mail missing 'Precedence: bulk' header. "
                        "SpamAssassin and several legacy filters give a small "
                        "negative weight for bulk mail that doesn't declare "
                        "itself. Easy fix at the ESP / sending tool."
                    ),
                )
            )

    lu = email.headers.get("list-unsubscribe", [])
    lu_post = email.headers.get("list-unsubscribe-post", [])

    if lu:
        findings.append(
            Finding(
                check="content.list_unsubscribe_header",
                severity=Severity.INFO,
                passed=True,
                message="List-Unsubscribe header present.",
                details={"value": lu[0][:200]},
            )
        )
    elif not bulk:
        # 1:1 personal mail doesn't need List-Unsubscribe — PASS with context.
        findings.append(
            Finding(
                check="content.list_unsubscribe_header",
                severity=Severity.INFO,
                passed=True,
                message="Not applicable: 1:1 mail (no bulk signals).",
                details={"is_bulk": False},
            )
        )
    else:
        findings.append(
            Finding(
                check="content.list_unsubscribe_header",
                severity=Severity.CRITICAL,
                passed=False,
                message=(
                    "This is bulk mail with no one-click unsubscribe. Gmail, Yahoo, "
                    "and Microsoft have rejected bulk mail without it since 2024. "
                    "Turn on one-click unsubscribe in your sending tool. It is "
                    "sometimes labelled List-Unsubscribe."
                ),
                details={"is_bulk": True},
            )
        )

    if lu_post and _ONE_CLICK_RX.search(lu_post[0]):
        findings.append(
            Finding(
                check="content.list_unsubscribe_post",
                severity=Severity.INFO,
                passed=True,
                message="One-click unsubscribe is on, and a reader can leave in one click.",
            )
        )
    elif not bulk:
        findings.append(
            Finding(
                check="content.list_unsubscribe_post",
                severity=Severity.INFO,
                passed=True,
                message="Not applicable: 1:1 mail (no bulk signals).",
                details={"is_bulk": False},
            )
        )
    else:
        findings.append(
            Finding(
                check="content.list_unsubscribe_post",
                severity=Severity.CRITICAL,
                passed=False,
                message=(
                    "Your unsubscribe link works, but a reader cannot leave in one "
                    "click. Gmail and Yahoo require the one-click form on bulk mail. "
                    "Your sending tool labels this List-Unsubscribe-Post, or simply "
                    "one-click unsubscribe."
                ),
                details={"is_bulk": True, "raw": (lu_post[0] if lu_post else None)},
            )
        )

    # Visible body unsubscribe link + clip risk.
    if email.html:
        soup = BeautifulSoup(email.html, "html.parser")
        anchor = _find_unsub_anchor(soup)
        if anchor is None:
            findings.append(
                Finding(
                    check="content.unsubscribe_link_body",
                    severity=Severity.MEDIUM,
                    passed=False,
                    message=(
                        "No visible unsubscribe link found in HTML body. "
                        "Required by Gmail/Yahoo sender guidelines."
                    ),
                )
            )
        else:
            findings.append(
                Finding(
                    check="content.unsubscribe_link_body",
                    severity=Severity.INFO,
                    passed=True,
                    message="Visible unsubscribe link present in body.",
                    details={"href": (anchor.get("href") or "")[:120]},
                )
            )
            # Clip risk: if HTML > 102KB and the unsub anchor sits past the
            # 102KB offset, Gmail silently hides it → user hits Report Spam.
            html_bytes = len(email.html.encode("utf-8"))
            if html_bytes > GMAIL_CLIP_BYTES:
                offset = _byte_offset_of_anchor(email.html, str(anchor))
                if offset is not None and offset > GMAIL_CLIP_BYTES:
                    findings.append(
                        Finding(
                            check="render.unsub_clipped",
                            severity=Severity.CRITICAL,
                            passed=False,
                            message=(
                                f"Unsubscribe link at byte offset {offset:,} is past "
                                f"Gmail's {GMAIL_CLIP_BYTES:,} clip threshold; users "
                                f"won't see it and may click Report Spam instead."
                            ),
                            details={"offset": offset, "clip": GMAIL_CLIP_BYTES},
                        )
                    )

    return findings
