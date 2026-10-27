"""Transform a test send into a production-shaped email.

A test send is the SAME content the recipient would get in production
PLUS a few markers (test prefix in subject, ESP test headers, raw
merge tags). Cleanup strips those markers so the audit scores what
production would actually look like.

Idempotent: cleanup applied twice yields the same result. Safe to
call on production emails too — it'll find nothing to clean and return
the same ParsedEmail.

Returns (cleaned_email, CleanupReport). The report lists every action
taken so the audit report can show the user exactly what was changed.

`ParsedEmail.raw` (the underlying EmailMessage) is NOT rebuilt —
attachment_risk.py is the only check that reads it, and attachments
don't change between test and production. Document if that assumption
breaks.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from email.utils import formataddr, getaddresses

from .parse import ParsedEmail

_SUBJECT_PREFIX_RX = re.compile(
    r"^(\s*\[?\s*(test|preview|sandbox|dev|staging|draft|qa|uat)\s*\]?\s*[\-:_\]\)|]\s*)+",
    re.IGNORECASE,
)

_HEADERS_TO_STRIP = (
    "x-test",
    "x-test-send",
    "x-preview-send",
    "x-mailchimp-test",
    "x-mailgun-test",
    "x-klaviyo-test",
    "x-hubspot-test",
    "x-sendgrid-test",
    "x-ac-test",
    "x-brevo-test",
)

_HEADER_VALUE_TESTS = {
    "x-mailin-type": ("template-test", "test"),
}

_FAKE_FIRST_NAMES = ("Sarah", "Marcus", "Priya", "Ahmed", "Emma", "Noah", "Léa", "Kai")
_FAKE_LAST_NAMES = ("Chen", "Patel", "Garcia", "Kowalski", "Okafor", "Müller")
_FAKE_FULL_NAMES = tuple(
    f"{first} {last}" for first in _FAKE_FIRST_NAMES[:4] for last in _FAKE_LAST_NAMES[:2]
)
_FAKE_EMAIL = "sarah.chen@example-recipient.com"
_FAKE_COMPANY = "Northwind Realty"
_FAKE_CITY = "Toronto"
_FAKE_UNSUB_URL = "https://list.example.com/unsubscribe?token=fakeUnsub123"
_FAKE_LINK_URL = "https://www.example.com/landing?utm_source=audit"


def _pick_fake(field_name: str) -> str:
    n = field_name.lower().replace(" ", "").replace("_", "").replace("-", "").replace(".", "")
    # URL-shaped fields first — they must not collapse to a first name
    # because link_quality / url_reputation checks parse them as hrefs.
    if "unsub" in n or "unsubscribe" in n:
        return _FAKE_UNSUB_URL
    if n in ("url", "link", "href") or n.endswith(("url", "link")) or "viewinbrowser" in n:
        return _FAKE_LINK_URL
    if "firstname" in n or n in ("fname", "first"):
        return random.choice(_FAKE_FIRST_NAMES)
    if "lastname" in n or n in ("lname", "last", "surname"):
        return random.choice(_FAKE_LAST_NAMES)
    if "fullname" in n or n == "name":
        return random.choice(_FAKE_FULL_NAMES)
    if "email" in n:
        return _FAKE_EMAIL
    if "company" in n or "organization" in n or n == "org":
        return _FAKE_COMPANY
    if "city" in n:
        return _FAKE_CITY
    return random.choice(_FAKE_FIRST_NAMES)


# Keywords that signal a `[…]` interior is a personalization placeholder.
# Conservative on purpose — MSO Outlook conditional comments (`[if mso]`,
# `[endif]`) and CSS-bracket selectors must not be substituted, so we
# only replace brackets whose interior has at least one of these tokens.
_PLACEHOLDER_KEYWORDS = (
    "name",
    "first",
    "last",
    "full",
    "email",
    "company",
    "city",
    "country",
    "phone",
    "url",
    "link",
    "unsub",
    "merge",
    "tag",
    "field",
    "goes here",
    "fallback",
    "recipient",
    "subscriber",
)
_PLACEHOLDER_SKIP = ("if mso", "endif", "mso ", "outlook", "endif]")


def _is_placeholder_bracket(content: str) -> bool:
    """True if the interior of `[…]` looks like a personalization field.

    Skips Outlook MSO conditional comments (`[if mso]…[endif]`) and
    anything with no clear placeholder keyword.
    """
    cl = content.strip().lower()
    if not cl or any(s in cl for s in _PLACEHOLDER_SKIP):
        return False
    return any(k in cl for k in _PLACEHOLDER_KEYWORDS)


_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("jinja", re.compile(r"\{\{\s*([A-Za-z_][\w\.\- ]*?)\s*(?:\|[^\}]+)?\s*\}\}")),
    ("liquid_block", re.compile(r"\{%\s*([A-Za-z_][\w\.\- ]*?)\s*%\}")),
    ("mailchimp", re.compile(r"\*\|\s*([A-Za-z_][\w\.\- ]*?)\s*\|\*")),
    ("ac_percent", re.compile(r"%([A-Z][A-Z0-9_]+)%")),
    ("double_percent", re.compile(r"%%\s*([A-Za-z_][\w\.\- ]*?)\s*%%")),
    ("double_bracket", re.compile(r"\[\[\s*([A-Za-z_][\w\.\- ]*?)\s*\]\]")),
    # Keyword-gated single-bracket sniffer. Covers Kit's
    # `[FIRST NAME GOES HERE]`, Campaign Monitor's
    # `[firstname,fallback=friend]`, Constant Contact's
    # `[Recipient FirstName]`, and similar one-off ESP idioms without
    # eating MSO conditional comments.
    ("placeholder_bracket", re.compile(r"\[([^\[\]\n]{1,80})\]")),
)


@dataclass
class CleanupReport:
    subject_prefix_stripped: str | None = None
    headers_stripped: list[str] = field(default_factory=list)
    placeholders_substituted: list[dict] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(
            self.subject_prefix_stripped or self.headers_stripped or self.placeholders_substituted
        )


def _strip_subject_prefix(subject: str | None, report: CleanupReport) -> str | None:
    if not subject:
        return subject
    m = _SUBJECT_PREFIX_RX.match(subject)
    if not m:
        return subject
    report.subject_prefix_stripped = m.group(0).rstrip()
    cleaned = subject[m.end() :].lstrip()
    return cleaned or subject


def _strip_test_headers(
    headers: dict[str, list[str]], report: CleanupReport
) -> dict[str, list[str]]:
    out = {k: list(v) for k, v in headers.items()}
    for name in _HEADERS_TO_STRIP:
        if name in out:
            report.headers_stripped.append(name)
            del out[name]
    for name, needles in _HEADER_VALUE_TESTS.items():
        if name not in out:
            continue
        kept = [v for v in out[name] if not any(n in v.lower() for n in needles)]
        if len(kept) != len(out[name]):
            report.headers_stripped.append(name)
        if kept:
            out[name] = kept
        else:
            del out[name]
    return out


def _substitute_address_header(value: str | None, report: CleanupReport) -> str | None:
    """Substitute placeholders inside display names only.

    Header value is `"Display Name" <user@dom>` (possibly comma-separated).
    Addresses must be left exact — they drive auth/alignment checks. The
    display-name half is composer-controlled and can carry merge tags
    (`From: "Hi {{first_name}}" <newsletter@example.com>`).
    """
    if not value:
        return value
    pairs = getaddresses([value])
    if not pairs:
        return value
    out_pairs: list[tuple[str, str]] = []
    for display, addr in pairs:
        if display:
            cleaned_display = _substitute_placeholders(display, report) or display
            out_pairs.append((cleaned_display, addr))
        else:
            out_pairs.append((display, addr))
    return ", ".join(formataddr(p) for p in out_pairs)


def _substitute_placeholders(text: str | None, report: CleanupReport) -> str | None:
    if not text:
        return text
    out = text
    for pattern_name, rx in _PATTERNS:

        def _sub(m: re.Match[str], pn: str = pattern_name) -> str:
            field_name = m.group(1) if m.lastindex else ""
            # Generic bracket sniffer is keyword-gated to avoid eating
            # MSO Outlook conditionals (`[if mso]`/`[endif]`).
            if pn == "placeholder_bracket" and not _is_placeholder_bracket(field_name):
                return m.group(0)
            fake = _pick_fake(field_name)
            report.placeholders_substituted.append(
                {"pattern": pn, "field": field_name.strip(), "substituted": fake}
            )
            return fake

        out = rx.sub(_sub, out)
    return out


def cleanup(email: ParsedEmail) -> tuple[ParsedEmail, CleanupReport]:
    """Return a new ParsedEmail with test markers removed + placeholders
    substituted, plus a CleanupReport listing what changed.

    Original ParsedEmail is not mutated. `email.raw` is shared by
    reference (only attachment_risk reads it; attachments unchanged).
    """
    report = CleanupReport()

    # Subject: strip TEST prefix, then substitute placeholders in the
    # remainder. A bare `Hi [FIRST NAME]` subject lands here.
    cleaned_subject = _strip_subject_prefix(email.subject, report)
    cleaned_subject = _substitute_placeholders(cleaned_subject, report)

    cleaned_headers = _strip_test_headers(email.headers, report)
    if cleaned_subject != email.subject:
        cleaned_headers["subject"] = [cleaned_subject] if cleaned_subject else []

    # From / Reply-To / To display names — composer-controlled, can carry
    # merge tags. Substitute in-place; preserve the address half exactly
    # so auth/alignment checks see the real domain.
    cleaned_from = _substitute_address_header(email.from_addr, report)
    if cleaned_from and cleaned_from != email.from_addr:
        cleaned_headers["from"] = [cleaned_from]
    cleaned_to = [_substitute_address_header(addr, report) or addr for addr in email.to_addrs]
    if cleaned_to != email.to_addrs:
        cleaned_headers["to"] = [v for v in cleaned_to if v]
    for hdr in ("reply-to", "sender"):
        if hdr in cleaned_headers:
            cleaned_headers[hdr] = [
                _substitute_address_header(v, report) or v for v in cleaned_headers[hdr]
            ]

    cleaned_html = _substitute_placeholders(email.html, report)
    cleaned_plain = _substitute_placeholders(email.plain_text, report)

    cleaned = ParsedEmail(
        raw=email.raw,
        headers=cleaned_headers,
        html=cleaned_html,
        plain_text=cleaned_plain,
        from_addr=cleaned_from,
        received_at=email.received_at,
        to_addrs=cleaned_to,
        subject=cleaned_subject,
        authentication_results=list(email.authentication_results),
    )
    return cleaned, report
