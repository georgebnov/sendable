"""Orchestrator for the domain-health audit phase.

Public API: `run_domain_health(parsed_email) -> list[Finding]`. Extracts
the sender's registrable domain, fans out the v1 mxtoolbox-style checks
in parallel, returns the merged findings list.

Errors during DNS / SMTP / HTTPS probes are caught inside each check and
surfaced as INFO findings; this runner never raises.
"""

from __future__ import annotations

import asyncio

from .. import esp as esp_detect
from ..parse import ParsedEmail
from ..report import Finding
from ..severity import Severity
from .dns import (
    blacklist,
    dkim,
    dmarc,
    dns_infra,
    modern_records,
    sender_dbl,
    sending_ip_dns,
    smtp_probe,
    spf,
    url_reputation,
)
from .dns_client import query as dns_query

# Known managed-mail operators. Detected by inspecting the sender
# domain's MX records — if the MX hostnames live under one of these
# suffixes, the apex (e.g. outlook.com) owns the SMTP banner / PTR /
# STARTTLS / TLS-version checks. Flagging "your mail-server reverse DNS
# doesn't match" against Microsoft 365 is misleading: every M365
# customer has identical "mismatches" by design.
_MAIL_OPERATORS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Microsoft 365", ("protection.outlook.com", "olc.protection.outlook.com")),
    (
        "Google Workspace",
        (
            "google.com",
            "googlemail.com",
            "aspmx.l.google.com",
            "googleusercontent.com",
        ),
    ),
    ("Mimecast", ("mimecast.com", "mimecast-offshore.com")),
    ("Proofpoint", ("ppe-hosted.com", "pphosted.com")),
    ("Fastmail", ("messagingengine.com",)),
    ("Zoho Mail", ("zoho.com", "zohomail.com")),
    ("Yahoo / AOL", ("yahoodns.net", "aol.com")),
)


async def _detect_mail_operator(domain: str) -> str | None:
    """Return the managed-mail-operator name (e.g. 'Microsoft 365')
    when the sender domain's MX records resolve under that operator's
    apex, else None. The check is best-effort — DNS failures return
    None so the caller falls through to the usual probe path."""
    ans = await dns_query(domain, "MX")
    if not ans.ok or not ans.records:
        return None
    hosts = " ".join(ans.records).lower()
    for name, suffixes in _MAIL_OPERATORS:
        if any(suffix in hosts for suffix in suffixes):
            return name
    return None


def _demote_to_info(findings: list[Finding], operator: str) -> list[Finding]:
    """Collapse failing findings to INFO when a managed mail operator
    owns them. Preserves the finding (still visible in the technical
    breakdown) but the scorer no longer deducts. We update the message
    so the technical breakdown explains why."""
    out: list[Finding] = []
    for f in findings:
        if f.passed:
            out.append(f)
            continue
        out.append(
            f.model_copy(
                update={
                    "severity": Severity.INFO,
                    "message": (
                        f"[managed by {operator}] {f.message} "
                        f"This is your mail-operator's infrastructure, not your "
                        f"domain — there is nothing to fix here."
                    ),
                    "source": "domain_config",
                }
            )
        )
    return out


def _registrable_from(parsed: ParsedEmail) -> str | None:
    """Reuses the same registrable extractor used by audit.copywriting.link_quality
    and memory.derived. Lazy-import keeps this module importable in isolation."""
    from email.utils import parseaddr

    from engine.copywriting.link_quality import _registrable

    raw = parsed.from_addr
    if not raw:
        return None
    _, mailbox = parseaddr(raw)
    if not mailbox or "@" not in mailbox:
        return None
    host = mailbox.split("@", 1)[1].lower().strip()
    if not host:
        return None
    return _registrable(host)


async def run_domain_health(parsed: ParsedEmail) -> list[Finding]:
    domain = _registrable_from(parsed)
    if not domain:
        return [
            Finding(
                check="domain_health.sender_extraction",
                severity=Severity.INFO,
                passed=False,
                message="Could not extract sender domain from From: header.",
            )
        ]

    # Detect ESP up front. When the sender routes through a major ESP
    # (Kit, Mailchimp, Klaviyo, SendGrid, etc.), the outbound IP belongs
    # to the ESP, not the marketer — and any large ESP has at least one
    # IP listed on a noisy RBL at any given time. Flagging "your sending
    # IP is listed" against ESP infra is misleading and not actionable.
    # Skip the IP-RBL fan-out when a high-confidence ESP profile fires;
    # emit a single INFO finding so the report explains why.
    detected = esp_detect.detect(parsed)
    # Hold the narrowed profile, not a bool: the branches below read esp.name,
    # and `esp is not None` is what proves that access is safe.
    esp = detected if (detected is not None and detected.is_high_confidence()) else None

    async def _blacklist_or_skip() -> list[Finding]:
        if esp is not None:
            return [
                Finding(
                    check="blacklist.skipped_esp",
                    severity=Severity.INFO,
                    passed=True,
                    message=(
                        f"Sending-IP blacklist scan skipped — outbound IP belongs to "
                        f"{esp.name}, not to your domain. Major ESPs always have "
                        f"some IPs on RBLs (shared pool churn); flagging them as "
                        f"your problem would be misleading."
                    ),
                    details={"esp": esp.name, "confidence": esp.confidence},
                )
            ]
        return await blacklist.run(parsed.headers)

    # Detect managed mail operator (M365 / Google Workspace / etc.) so
    # SMTP-side findings get demoted: those servers are run by the
    # operator, not the marketer, and produce the same "PTR mismatch",
    # "no STARTTLS", "banner mismatch" noise for every customer.
    mail_operator = await _detect_mail_operator(domain)

    (
        spf_f,
        dmarc_f,
        dkim_f,
        modern_f,
        blacklist_f,
        smtp_f,
        url_f,
        dns_infra_f,
        sender_dbl_f,
        sending_ip_f,
    ) = await asyncio.gather(
        spf.run(domain),
        dmarc.run(domain),
        dkim.run(domain, parsed.headers),
        modern_records.run(domain),
        _blacklist_or_skip(),
        smtp_probe.run(domain),
        url_reputation.run(parsed, domain),
        dns_infra.run(domain),
        sender_dbl.run(domain),
        sending_ip_dns.run(parsed.headers),
        return_exceptions=False,
    )

    # PTR/FCrDNS demotion: when sending IP belongs to a known ESP, the
    # marketer cannot fix the published reverse DNS — demote to INFO so
    # the report still surfaces it but the scorer doesn't deduct.
    if esp is not None:
        sending_ip_f = sending_ip_dns.demote_to_info_when_esp(sending_ip_f, esp.name)

    if mail_operator:
        # Mail-server-side: pure operator infra → no marketer action.
        smtp_f = _demote_to_info(smtp_f, mail_operator)
        smtp_f.insert(
            0,
            Finding(
                check="smtp.managed_operator",
                severity=Severity.INFO,
                passed=True,
                message=(
                    f"Mail-server infrastructure managed by {mail_operator}. "
                    f"SMTP-side checks (MX shape, open relay) demoted — the "
                    f"operator owns every one of them; nothing for the "
                    f"marketer to fix."
                ),
                details={"operator": mail_operator},
            ),
        )

    return [
        *spf_f,
        *dmarc_f,
        *dkim_f,
        *modern_f,
        *blacklist_f,
        *smtp_f,
        *url_f,
        *dns_infra_f,
        *sender_dbl_f,
        *sending_ip_f,
    ]
