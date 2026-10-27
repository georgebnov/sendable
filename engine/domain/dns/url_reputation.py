"""URL-reputation fan-out: every registrable domain in the body's hrefs
is queried against Spamhaus DBL + SURBL multi.

Body URLs that resolve to listed domains are how `554 5.7.1 Message
refused by SURBL check` fires inside Microsoft `550 5.7.350` NDRs.
Reputation of *linked* domains is doc §6 critical — a single bit.ly
caught Postmark's customer in spam in their 2024 case study.

Mechanics: same as IP RBLs but with the registrable domain (not reverse
IP) prepended to the DBL host. Spamhaus DBL response codes encode list
type:
  127.0.1.2  → spam domain (DBL)
  127.0.1.4  → phish domain
  127.0.1.5  → malware domain
  127.0.1.6  → botnet C&C
  127.0.1.102 → abused legit redirector
  127.0.1.103 → abused URL shortener
  127.255.255.255 → query refused (rate-limited)

Common-domain skip: don't waste lookups on first-party (sender's own
domain) or ubiquitous infra (google.com, microsoft.com, ...).

Doc tier: §6 (Reputation of linked domains: SURBL/Spamhaus DBL/URIBL).
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from ...copywriting.link_quality import _registrable
from ...parse import ParsedEmail
from ...report import Finding
from ...severity import Severity
from ..dns_client import query

# (label, dbl-host, severity_when_listed, blurb). mxtoolbox's "Domain
# Blacklist" tier covers Spamhaus DBL + SURBL + ivmURI + Nordspam DBL +
# SEM (FRESH/URI/URIRED) + URIBL multi.  SORBS RHSBL family removed
# (decommissioned June 2024).
_DBLS = [
    # ─── Tier 1: industry-standard ────────────────────────────────────
    (
        "spamhaus_dbl",
        "dbl.spamhaus.org",
        Severity.HIGH,
        "Spamhaus Domain Block List: most-consulted URL reputation list. A real listing here "
        "directly hurts inbox placement at every major receiver.",
    ),
    (
        "surbl_multi",
        "multi.surbl.org",
        Severity.HIGH,
        "SURBL multi: covers phish/malware/abuse listings. Many corporate filters chain through "
        "this.",
    ),
    (
        "uribl_multi",
        "multi.uribl.com",
        Severity.HIGH,
        "URIBL multi: combined list (BLACK + GREY + RED). Bitmask response: "
        "2=BLACK, 4=GREY, 8=RED.",
    ),
    # ─── Tier 2: medium ───────────────────────────────────────────────
    (
        "ivm_uri",
        "uri.ivmuri.org",
        Severity.MEDIUM,
        "Invaluement IPv4 URI: paid subscription list of abused URI domains.",
    ),
    (
        "nordspam_dbl",
        "dbl.nordspam.com",
        Severity.MEDIUM,
        "Nordspam DBL: Nordic anti-spam URL reputation.",
    ),
    (
        "sem_fresh",
        "fresh.spameatingmonkey.net",
        Severity.MEDIUM,
        "Spam Eating Monkey FRESH: recently-registered domains used in spam.",
    ),
    (
        "sem_uri",
        "uribl.spameatingmonkey.net",
        Severity.MEDIUM,
        "Spam Eating Monkey URIBL: domains found in spam URIs.",
    ),
    (
        "sem_urired",
        "urired.spameatingmonkey.net",
        Severity.MEDIUM,
        "Spam Eating Monkey URIRED: redirector/cloaker domains.",
    ),
]

# Account for 80%+ of links in normal mail; almost never listed.
_SKIP_DOMAINS = frozenset(
    {
        "google.com",
        "youtube.com",
        "googleusercontent.com",
        "microsoft.com",
        "office.com",
        "bing.com",
        "apple.com",
        "icloud.com",
        "amazon.com",
        "amazonaws.com",
        "cloudfront.net",
        "facebook.com",
        "instagram.com",
        "twitter.com",
        "x.com",
        "linkedin.com",
        "github.com",
        "wikipedia.org",
        "mozilla.org",
        "w3.org",
    }
)

# Administrative-error sentinels — NOT real listings, NOT clean either.
# 127.0.0.1 is URIBL/SURBL "Query Refused"; 127.255.255.x is the
# Spamhaus/Barracuda public-resolver / rate-limit / typo signal. Reading
# any of these as a hit produces false positives; ignoring them as clean
# produces false negatives. Surface as inconclusive instead.
_DBL_SENTINELS = frozenset(
    {
        "127.0.0.1",
        "127.255.255.252",
        "127.255.255.254",
        "127.255.255.255",
    }
)


def _body_domains(email: ParsedEmail, sender_domain: str | None) -> list[str]:
    """Distinct registrable domains from <a href> in HTML body."""
    if not email.html:
        return []
    soup = BeautifulSoup(email.html, "lxml")
    out: list[str] = []
    seen: set[str] = set()
    for a in soup.find_all("a", href=True):
        href = (a.get("href") or "").strip()
        if not href:
            continue
        try:
            u = urlparse(href)
        except Exception:
            continue
        host = (u.hostname or "").lower()
        if not host or u.scheme not in ("http", "https"):
            continue
        reg = _registrable(host)
        if not reg:
            continue
        if reg == sender_domain:
            continue
        if reg in _SKIP_DOMAINS:
            continue
        if reg in seen:
            continue
        seen.add(reg)
        out.append(reg)
    return out


async def _check_one(
    domain: str, label: str, dbl_host: str, severity: Severity, blurb: str
) -> Finding | None:
    qname = f"{domain}.{dbl_host}"
    ans = await query(qname, "A")
    # NXDOMAIN = definitively clean.
    if ans.error == "nxdomain":
        return None
    # No records returned at all (no_answer): clean-ish, treat as not-listed.
    if ans.ok and not ans.records:
        return None
    if not ans.ok:
        # Timeout / SERVFAIL / no_nameservers — can't tell. Don't emit
        # per-domain noise here; rolled-up "scan completed" finding above
        # already implicitly says "we tried". Caller could log if needed.
        return None
    real = [r for r in ans.records if r not in _DBL_SENTINELS]
    if not real:
        return None  # sentinel-only response → inconclusive, not a hit
    return Finding(
        check=f"url_reputation.{label}",
        severity=severity,
        passed=False,
        message=(
            f"A domain you link to, '{domain}', is on the {label} blocklist "
            f"({dbl_host}). {blurb} A receiver can bounce the whole message because "
            "of that one link. The bounce reads 554 5.7.1 or 550 5.7.350. Remove the "
            "link, or ask the owner of that domain to clear the listing."
        ),
        details={
            "domain": domain,
            "dbl": dbl_host,
            "response": list(ans.records),
            "blurb": blurb,
        },
    )


async def run(parsed: ParsedEmail, sender_domain: str | None) -> list[Finding]:
    domains = _body_domains(parsed, sender_domain)
    if not domains:
        return [
            Finding(
                check="url_reputation.scanned",
                severity=Severity.INFO,
                passed=True,
                message="No external link domains in body to scan.",
            )
        ]

    tasks = [
        _check_one(d, label, host, sev, blurb)
        for d in domains
        for (label, host, sev, blurb) in _DBLS
    ]
    results = await asyncio.gather(*tasks)
    hits = [f for f in results if f is not None]

    findings: list[Finding] = [
        Finding(
            check="url_reputation.scanned",
            severity=Severity.INFO,
            passed=True,
            message=(
                f"Scanned {len(domains)} body link domain(s) against {len(_DBLS)} URL blacklist(s)."
            ),
            details={"domains_scanned": domains, "dbls": [h for _, h, _, _ in _DBLS]},
        )
    ]
    findings.extend(hits)
    if not hits:
        findings.append(
            Finding(
                check="url_reputation.no_listings",
                severity=Severity.INFO,
                passed=True,
                message="No body-link domain is currently listed on Spamhaus DBL or SURBL.",
            )
        )
    return findings
