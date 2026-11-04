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

A list that gave no usable answer is not clean: it goes into
`sender_dbl.unverified`, and the clean summary stays away.

Doc tier: §6 (Reputation of sender domain).
"""

from __future__ import annotations

import asyncio

from ...report import Finding
from ...severity import Severity
from ..dns_client import DnsAnswer, query
from .list_reading import Reading, not_checked, read_answer, unverified_finding
from .url_reputation import _DBLS, working_lists


def _listed_finding(
    domain: str,
    label: str,
    dbl_host: str,
    blurb: str,
    ans: DnsAnswer,
    test_passed: bool,
) -> Finding:
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
            "test_passed": test_passed,
            "blurb": blurb,
        },
        source="domain_config",
        hard_gate=True,
    )


async def run(domain: str) -> list[Finding]:
    working, answers = await asyncio.gather(
        working_lists(),
        asyncio.gather(*[query(f"{domain}.{host}", "A") for _, host, _, _ in _DBLS]),
    )

    hits: list[Finding] = []
    unchecked: list[dict[str, str]] = []
    for (label, host, _sev, blurb), ans in zip(_DBLS, answers, strict=True):
        test_passed = host in working
        reading = read_answer(ans, test_passed=test_passed)
        if reading is Reading.LISTED:
            hits.append(_listed_finding(domain, label, host, blurb, ans, test_passed))
        elif reading is Reading.UNKNOWN:
            unchecked.append(not_checked(host, domain, ans))

    findings: list[Finding] = [
        Finding(
            check="sender_dbl.scanned",
            severity=Severity.INFO,
            passed=True,
            message=(
                f"Scanned sender apex '{domain}' against {len(_DBLS) - len(unchecked)} of "
                f"{len(_DBLS)} URL blacklist(s)."
            ),
            details={"domain": domain, "dbls": [h for _, h, _, _ in _DBLS]},
            source="domain_config",
        )
    ]
    findings.extend(hits)
    if unchecked:
        findings.append(
            unverified_finding(
                "sender_dbl.unverified",
                unchecked,
                len(_DBLS),
                "your sending domain",
                source="domain_config",
            )
        )
    elif not hits:
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
