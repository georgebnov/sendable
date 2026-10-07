"""TLS transport check: did the last external SMTP hop use TLS?

Gmail (post-Feb 2024) and Microsoft (post-May 2025) both require outbound
mail to land over TLS. Plain-text submission is bulk-rejected.

Detection is header-only. RFC 3848 §1 says receivers annotate the
Received header with `with ESMTPS` when STARTTLS-encrypted, `with ESMTP`
when plain. Many MTAs additionally append `(version=TLS1_3 cipher=...)`
or `using TLSv1.3`. We treat the presence of any of these markers as
"TLS used."

Hop selection mirrors `audit/domain_health/checks/blacklist.py`'s
`extract_sender_ip()`: walk the Received chain oldest-first (chain is
ordered newest-on-top, so iterate reversed), pick the first hop whose
`from <host> ([public-ipv4])` field shows a public IPv4. That hop is the
handoff from external sender to receiver — the place where TLS or
plain-text submission actually happened.

Demoted to INFO when sending IP belongs to a known ESP. Every major ESP
(SendGrid / Mailchimp / Brevo / Klaviyo / Mailgun / etc.) submits over
TLS as hard policy; a missing marker in that case is a header-sanitization
artifact, not an actual plain-text send.
"""

from __future__ import annotations

import re

from ... import esp as esp_detect
from ...parse import ParsedEmail
from ...report import Finding
from ...severity import Severity
from ..dns.blacklist import (
    _IPV4_RX,
    _RECEIVED_FROM_RX,
    _is_public_ipv4,
)

# RFC 3848: `with ESMTPS` = STARTTLS-encrypted. Common variants:
# UTF8SMTPS (RFC 6531), LMTPS, plus the free-form annotations many MTAs
# tack on: `(using TLSv1.3 ...)`, `(version=TLS1_3 ...)`.
_TLS_MARKERS_RX = re.compile(
    r"\b(?:with\s+(?:E?SMTPS|UTF8SMTPS|LMTPS)"
    r"|using\s+TLSv?\d"
    r"|version=TLSv?\d"
    r"|STARTTLS)\b",
    re.IGNORECASE,
)


def _last_external_hop(received_chain: list[str]) -> str | None:
    """Return the Received hop string at which mail entered receiver
    infra. Oldest hop is at the bottom of the chain — iterate reversed."""
    for hop in reversed(received_chain):
        m = _RECEIVED_FROM_RX.search(hop)
        if m and _is_public_ipv4(m.group(1)):
            return hop
        for ip in _IPV4_RX.findall(hop):
            if _is_public_ipv4(ip):
                return hop
    return None


async def run(email: ParsedEmail) -> list[Finding]:
    chain = list(email.headers.get("received", []))
    if not chain:
        return [Finding(
            check="auth.tls_transport",
            severity=Severity.INFO,
            passed=False,
            message=(
                "No Received headers — cannot evaluate transport TLS. "
                "Likely a forwarded or ARC-rewritten message."
            ),
        )]

    hop = _last_external_hop(chain)
    if hop is None:
        return [Finding(
            check="auth.tls_transport",
            severity=Severity.INFO,
            passed=False,
            message=(
                "Could not locate the last external SMTP hop in Received "
                "chain (no public IPv4 found). TLS transport check skipped."
            ),
        )]

    has_tls = bool(_TLS_MARKERS_RX.search(hop))
    profile = esp_detect.detect(email)
    is_esp = profile is not None and profile.is_high_confidence()

    if has_tls:
        return [Finding(
            check="auth.tls_transport",
            severity=Severity.INFO,
            passed=True,
            message=(
                "Last external SMTP hop used TLS (ESMTPS / STARTTLS / "
                "TLS marker present in Received header)."
            ),
            details={"hop": hop[:240]},
        )]

    if is_esp:
        return [Finding(
            check="auth.tls_transport",
            severity=Severity.INFO,
            passed=False,
            message=(
                f"[ESP outbound — {profile.name}] Last external hop has "
                "no TLS marker in its Received header. Major ESPs submit "
                "over TLS as hard policy; missing marker is a header-"
                "sanitization artifact at the relay, not an actual "
                "plain-text send."
            ),
            details={"hop": hop[:240], "esp": profile.name},
            source="esp_owned",
        )]

    return [Finding(
        check="auth.tls_transport",
        severity=Severity.HIGH,
        passed=False,
        message=(
            "Last external SMTP hop appears to be plain SMTP — no "
            "ESMTPS / STARTTLS / TLS marker found in the Received "
            "header. Gmail (2024+) and Microsoft (May 2025+) both "
            "require outbound mail to land over TLS; plain-text "
            "submission is bulk-rejected."
        ),
        details={"hop": hop[:240]},
    )]
