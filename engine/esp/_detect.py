"""ESP detection cascade.

Order: vendor headers (≈0.95) → Feedback-ID token (≈0.9) → DKIM `d=`
domain (≈0.75) → footer chrome markers (≈0.55). Each signal raises the
candidate's score; the highest scoring profile wins.

Why cascade instead of first-match: shared infrastructure. Kit signs
through SendGrid, so a "first DKIM hit wins" rule would mis-label Kit
sends as SendGrid. By scoring all signals and keeping the maximum, the
specific tokens (`:CK` in Feedback-ID, `Built with Kit` footer) beat the
generic SendGrid signing domain.
"""

from __future__ import annotations

import re
from email.utils import parseaddr
from urllib.parse import urlparse

from ..parse import ParsedEmail
from . import (
    activecampaign,
    brevo,
    campaignmonitor,
    constantcontact,
    hubspot,
    kit,
    klaviyo,
    mailchimp,
    mailgun,
    sendgrid,
)
from ._profile import ESPProfile, ProfileSpec

_SPECS: tuple[ProfileSpec, ...] = (
    kit.SPEC,
    mailchimp.SPEC,
    klaviyo.SPEC,
    hubspot.SPEC,
    activecampaign.SPEC,
    brevo.SPEC,
    mailgun.SPEC,
    campaignmonitor.SPEC,
    constantcontact.SPEC,
    # SendGrid LAST. Many ESPs route through it; specific profiles must
    # win before the generic fallback fires.
    sendgrid.SPEC,
)

_DKIM_D_RX = re.compile(r"\bd\s*=\s*([^;\s]+)", re.IGNORECASE)
_HREF_RX = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


def _dkim_domains(email: ParsedEmail) -> set[str]:
    """Signing domains the RECEIVER verified, not the ones the message claims.

    A DKIM-Signature header is written by the sender and anyone can put any `d=`
    in it. This signal scores 0.75, which is high confidence, and a high-confidence
    profile makes `run_domain_health` skip the entire IP blocklist scan. One line
    of `DKIM-Signature: d=kit.com` therefore disabled the blocklist fan-out for a
    listed sender.

    Authentication-Results is written by the receiving server after it checked the
    signature, so a `d=` naming a provider counts only when it appears there with
    `dkim=pass`.
    """
    verified = _verified_dkim_domains(email)
    if not verified:
        return set()
    out: set[str] = set()
    for raw in email.headers.get("dkim-signature", []):
        m = _DKIM_D_RX.search(raw)
        if m:
            claimed = m.group(1).strip().lower()
            if claimed in verified:
                out.add(claimed)
    return out


_AR_DKIM_PASS_RX = re.compile(
    r"\bdkim\s*=\s*pass\b[^;]*?\bheader\.(?:d|i)\s*=\s*@?([A-Za-z0-9.\-_]+)",
    re.IGNORECASE,
)


def _verified_dkim_domains(email: ParsedEmail) -> set[str]:
    """Domains the receiving server reported a passing DKIM signature for."""
    out: set[str] = set()
    for raw in email.authentication_results or []:
        for match in _AR_DKIM_PASS_RX.finditer(raw):
            out.add(match.group(1).strip().lower().lstrip("@"))
    return out


def _unsubscribe_hosts(email: ParsedEmail) -> set[str]:
    """Hosts found in List-Unsubscribe + any href containing 'unsubscribe'."""
    hosts: set[str] = set()
    for raw in email.headers.get("list-unsubscribe", []):
        for piece in re.findall(r"<([^>]+)>", raw):
            if piece.lower().startswith("http"):
                host = urlparse(piece).hostname
                if host:
                    hosts.add(host.lower())
            elif piece.lower().startswith("mailto:"):
                _, addr = parseaddr(piece[7:])
                if "@" in addr:
                    hosts.add(addr.split("@", 1)[1].lower())
    if email.html:
        for href in _HREF_RX.findall(email.html):
            if "unsubscribe" in href.lower():
                host = urlparse(href).hostname
                if host:
                    hosts.add(host.lower())
    return hosts


def detect(email: ParsedEmail) -> ESPProfile | None:
    """Return the best-matching ESPProfile, or None if no signal fires."""
    dkim = _dkim_domains(email)
    header_names = {k.lower() for k in email.headers}
    feedback_id = (email.headers.get("feedback-id") or [""])[0].lower()
    unsub_hosts = _unsubscribe_hosts(email)
    body_lower = ((email.html or "") + " " + (email.plain_text or "")).lower()

    best_spec: ProfileSpec | None = None
    best_score = 0.0
    for spec in _SPECS:
        s = spec.score(header_names, feedback_id, dkim, body_lower, unsub_hosts)
        if s > best_score:
            best_score = s
            best_spec = spec

    if best_spec is None or best_score == 0.0:
        return None
    return ESPProfile.from_spec(best_spec, best_score)
