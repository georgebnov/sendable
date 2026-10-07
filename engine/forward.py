"""Forwarded-email detection, content extraction, and score calibration.

A forwarded email (Gmail inline "Forward") replaces the original's headers
(DKIM signature, sending IP, TLS hop) and wraps the body in forward chrome.
Auditing it raw grades the FORWARD, not the campaign: auth checks fail on the
forwarder's signature, hygiene checks fire on forward-injected junk, and the
subject reads as deceptive because of the "Fwd:" prefix.

We handle both halves:
  - CONTENT survives in the forwarded body → `extract_original` strips the
    forward chrome so the copy / link / image checks grade the real email.
  - HEADERS are gone → `calibrate_for_forward` mutes the auth / transport /
    hidden-char findings (downgraded to INFO: visible, zero penalty), the same
    way free-mailbox calibration handles domains the sender can't own.

Only recoverable from an inline forward. A forward-as-attachment
(message/rfc822) should be unpacked upstream and audited as the real original.
"""

from __future__ import annotations

import dataclasses
import re

from bs4 import BeautifulSoup

from .parse import ParsedEmail
from .report import Finding
from .severity import Severity

_FWD_SUBJECT_RX = re.compile(r"^\s*(?:(?:fwd?|fw)\s*:\s*)+", re.IGNORECASE)
_FWD_BODY_MARKER_RX = re.compile(r"-{2,}\s*forwarded message\s*-{2,}", re.IGNORECASE)
# Mailbox providers that re-sign mail when it's forwarded.
_FORWARD_SIGNERS = ("gappssmtp.com",)
_HEADER_LINE_RX = re.compile(
    r"^\s*(from|date|sent|subject|to|cc|reply-to)\s*:", re.IGNORECASE
)

# Checks whose signal a forward destroys — muted, never scored on a forward.
# DKIM alignment on a forward is special: for an inline forward the person
# composed and sent it, so the outer signature is a pristine sample of THEIR
# sending account (e.g. Gmail signing as gappssmtp instead of their own
# domain). That's a real finding about the forwarder, not campaign noise, so we
# reframe it as a visible INFO note rather than quietly burying it.
_FORWARDER_ALIGN_PREFIX = "auth.dmarc_alignment"

# The rest are genuine transport / content artifacts of the forward hop —
# quietly muted (INFO, zero penalty).
_QUIET_MUTE_PREFIXES = (
    "auth.tls_transport",
    "auth.authentication_results",
    "sending_ip.",
    "content.zero_width",
    "content.bidi_override",
    "content.hidden_css_salting",
)

ADVISORY_CHECK = "delivery.forwarded"
_MUTE_NOTE = (
    "  (Muted: this is a forwarded copy, so this signal was rewritten in "
    "transit and isn't graded.)"
)


def is_forwarded(email: ParsedEmail) -> bool:
    """True when the email looks like a forward: a Fwd:/Fw: subject, a
    "Forwarded message" body marker, or a mailbox-provider forward signature."""
    if _FWD_SUBJECT_RX.match(email.subject or ""):
        return True
    body = f"{email.plain_text or ''} {email.html or ''}"
    if _FWD_BODY_MARKER_RX.search(body):
        return True
    for ar in email.authentication_results or []:
        if any(sig in ar.lower() for sig in _FORWARD_SIGNERS):
            return True
    return False


def _strip_subject(subject: str | None) -> str | None:
    if not subject:
        return subject
    return _FWD_SUBJECT_RX.sub("", subject).strip() or subject


def _strip_plain(plain: str | None) -> str | None:
    if not plain:
        return plain
    m = _FWD_BODY_MARKER_RX.search(plain)
    if not m:
        return plain
    lines = plain[m.end() :].splitlines()
    i = 0
    while i < len(lines) and not lines[i].strip():  # leading blank after marker
        i += 1
    while i < len(lines) and lines[i].strip() and _HEADER_LINE_RX.match(lines[i]):
        i += 1  # quoted From/Date/Subject/To header block
    while i < len(lines) and not lines[i].strip():  # blank before the body
        i += 1
    return "\n".join(lines[i:]).strip() or plain


def _strip_html(html: str | None) -> str | None:
    if not html:
        return html
    soup = BeautifulSoup(html, "lxml")
    quote = soup.find("div", class_="gmail_quote")
    if quote is None:
        return html
    attr = quote.find("div", class_="gmail_attr")
    if attr is not None:
        attr.decompose()
    inner = quote.decode_contents().strip()
    return inner or html


def extract_original(email: ParsedEmail) -> ParsedEmail:
    """A copy of `email` with the forward chrome stripped, so content checks
    grade the original campaign. Headers are left intact (muted later)."""
    return dataclasses.replace(
        email,
        subject=_strip_subject(email.subject),
        plain_text=_strip_plain(email.plain_text),
        html=_strip_html(email.html),
    )


def _forwarder_signing_note(f: Finding) -> str:
    """Reframe a forward's DKIM-alignment failure as a plain note about the
    forwarding account's own signing — visible and meaningful, not campaign
    noise. Pulls the signer + From domain from the finding's details."""
    d = f.details or {}
    signer = d.get("dkim_d")
    if isinstance(signer, list):
        signer = signer[0] if signer else None
    signer = signer or "a generic provider stamp"
    domain = d.get("from_org") or "its own domain"
    return (
        f"About the account that forwarded this: it signs its own email as "
        f"{signer}, not {domain}. That's the forwarding account's setup, not "
        f"this campaign, so it isn't scored here. But if this is your account, "
        f"your everyday emails aren't building {domain}'s reputation — worth "
        f"turning on your own signing."
    )


def calibrate_for_forward(findings: list[Finding]) -> list[Finding]:
    """Mute the checks a forward scrambles: downgrade to INFO (visible, zero
    penalty, hard-gate cleared) so the score reflects only what a forward
    preserves. Appends one advisory when anything was muted."""
    muted_any = False
    out: list[Finding] = []
    for f in findings:
        if f.passed:
            out.append(f)
        elif f.check.startswith(_FORWARDER_ALIGN_PREFIX):
            muted_any = True
            out.append(
                f.model_copy(
                    update={
                        "severity": Severity.INFO,
                        "hard_gate": False,
                        "message": _forwarder_signing_note(f),
                    }
                )
            )
        elif f.check.startswith(_QUIET_MUTE_PREFIXES):
            muted_any = True
            out.append(
                f.model_copy(
                    update={
                        "severity": Severity.INFO,
                        "hard_gate": False,
                        "message": f.message + _MUTE_NOTE,
                    }
                )
            )
        else:
            out.append(f)
    if muted_any:
        out.append(
            Finding(
                check=ADVISORY_CHECK,
                severity=Severity.INFO,
                passed=False,
                message=(
                    "This looks like a forwarded email. Forwarding rewrites the "
                    "sender's fingerprints (the signature, the sending server, "
                    "the encryption), so those checks were muted and left out of "
                    "the score. For a true read, send a test straight from your "
                    "email tool instead of forwarding."
                ),
            )
        )
    return out
