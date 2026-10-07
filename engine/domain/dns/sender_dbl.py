"""Sender-apex DBL lookup.

`url_reputation.py` checks every body LINK against Spamhaus DBL + SURBL +
URIBL etc. — phishing-style "I link to a known-bad shortener" risk. This
module runs the same list against the SENDER's own registrable domain. A
listing on the sender apex is far worse than a listed body link: every
major receiver (Gmail / Outlook / Yahoo / corporate filters) will junk or
hard-bounce mail from a DBL-listed apex regardless of content.

Why a separate module instead of folding into `url_reputation.py`:
 - severity ceiling differs (sender apex listing = CRITICAL, body link =
   HIGH);
 - the `_SKIP_DOMAINS` first-party shortcut in url_reputation is exactly
   the surface we want to scan here;
 - keeping the modules orthogonal lets the domain-health phase report
   "sender clean / body links clean" as two independent rows.

Doc tier: §6 (Reputation of sender domain).
"""

from __future__ import annotations

import asyncio

from ...report import Finding
from ...severity import Severity
from ..dns_client import query
from .url_reputation import _DBL_SENTINELS, _DBLS


async def _check_one(
    domain: str,
    label: str,
    dbl_host: str,
    blurb: str,
) -> Finding | None:
    qname = f"{domain}.{dbl_host}"
    ans = await query(qname, "A")
    if ans.error == "nxdomain":
        return None
    if ans.ok and not ans.records:
        return None
    if not ans.ok:
        return None
    real = [r for r in ans.records if r not in _DBL_SENTINELS]
    if not real:
        return None
    # Sender-apex listings are catastrophic — every receiver will junk or
    # bounce. Force CRITICAL regardless of how url_reputation rated this
    # DBL for body-link context.
    return Finding(
        check=f"sender_dbl.{label}",
        severity=Severity.CRITICAL,
        passed=False,
        message=(
            f"Sender domain '{domain}' is listed on {label} ({dbl_host}). "
            f"{blurb} Every major receiver will junk or bounce mail from "
            f"this apex until the listing is removed. Action: open a "
            f"removal request with the list operator and audit recent "
            f"send patterns for the spam signal that triggered the listing."
        ),
        details={
            "domain": domain,
            "dbl": dbl_host,
            "response": list(ans.records),
            "blurb": blurb,
        },
        source="domain_config",
        hard_gate=True,
    )


async def run(domain: str) -> list[Finding]:
    tasks = [_check_one(domain, label, host, blurb) for (label, host, _sev, blurb) in _DBLS]
    results = await asyncio.gather(*tasks)
    hits = [f for f in results if f is not None]

    findings: list[Finding] = [
        Finding(
            check="sender_dbl.scanned",
            severity=Severity.INFO,
            passed=True,
            message=f"Scanned sender apex '{domain}' against {len(_DBLS)} URL blacklist(s).",
            details={"domain": domain, "dbls": [h for _, h, _, _ in _DBLS]},
            source="domain_config",
        )
    ]
    findings.extend(hits)
    if not hits:
        findings.append(
            Finding(
                check="sender_dbl.no_listings",
                severity=Severity.INFO,
                passed=True,
                message=f"Sender apex '{domain}' is not listed on any scanned URL blacklist.",
                source="domain_config",
            )
        )
    return findings
