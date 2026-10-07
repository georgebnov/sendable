"""Free / consumer mailbox detection + score calibration.

A sender on a personal mailbox (gmail.com, yahoo.com, …) does not own that
domain and cannot publish SPF / DKIM / DMARC for it, so the authentication and
domain-record audit categories don't apply to them — penalising those is
unfair and makes a clean email read as "broken".

`calibrate_for_free_mailbox` drops the sender-auth / domain-record findings
(including the hard-gate alignment finding) and replaces them with one advisory
so the composite score reflects only what the sender controls. We do NOT hide
the underlying truth: sending marketing mail from a consumer mailbox is the #1
deliverability blocker (Gmail/Yahoo enforce DMARC on their own domains) — but
that's a "use your own domain" setup issue, surfaced as advice, not a content
defect that tanks the score.
"""

from __future__ import annotations

from email.utils import parseaddr

from .report import Finding
from .severity import Severity

# Known consumer mailbox providers (exact From-domain match).
FREE_MAILBOX_DOMAINS: frozenset[str] = frozenset(
    {
        "gmail.com",
        "googlemail.com",
        "yahoo.com",
        "yahoo.co.uk",
        "yahoo.ca",
        "ymail.com",
        "rocketmail.com",
        "outlook.com",
        "hotmail.com",
        "hotmail.co.uk",
        "live.com",
        "msn.com",
        "aol.com",
        "icloud.com",
        "me.com",
        "mac.com",
        "proton.me",
        "protonmail.com",
        "pm.me",
        "gmx.com",
        "gmx.net",
        "gmx.de",
        "zoho.com",
        "yandex.com",
        "mail.com",
    }
)

# Finding-check prefixes whose categories the sender can only control by owning
# their domain (authentication + domain_records). Mirrors the routing table in
# scoring._CATEGORY_BY_PREFIX.
_SENDER_AUTH_PREFIXES = (
    "auth.",
    "spf_record.",
    "dmarc_record.",
    "dkim_record.",
    "mta_sts.",
    "tlsrpt.",
    "bimi.",
)

ADVISORY_CHECK = "sender.free_mailbox"


def is_free_mailbox(from_addr: str | None) -> str | None:
    """Return the consumer-mailbox domain if `from_addr` is on a known free
    provider, else None. Tolerant of display-name forms and junk input."""
    if not from_addr:
        return None
    _, addr = parseaddr(from_addr)
    if "@" not in addr:
        return None
    domain = addr.rsplit("@", 1)[1].strip().lower().rstrip(".")
    return domain if domain in FREE_MAILBOX_DOMAINS else None


def calibrate_for_free_mailbox(findings: list[Finding], from_addr: str | None) -> list[Finding]:
    """When the From is a free mailbox, drop the sender-auth / domain-record
    findings and append one advisory. Otherwise return `findings` unchanged."""
    domain = is_free_mailbox(from_addr)
    if not domain:
        return findings
    kept = [f for f in findings if not f.check.startswith(_SENDER_AUTH_PREFIXES)]
    kept.append(
        Finding(
            check=ADVISORY_CHECK,
            severity=Severity.INFO,  # 0 penalty — visible, not score-affecting
            passed=False,
            message=(
                f"This email was sent from a personal {domain} address. Personal "
                f"mailboxes can't be authenticated for marketing — to run real "
                f"campaigns and clear spam filters, send from a domain you own. "
                f"Authentication and domain-record checks were skipped because "
                f"they don't apply to a mailbox you don't control."
            ),
            details={"from_domain": domain},
        )
    )
    return kept
