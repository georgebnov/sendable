"""IP RBL fan-out keyed on the sender's outbound public IP.

Standard RBL query: `<reversed-octets>.<rbl-host>` resolved as A. Any
non-sentinel answer = listed. NXDOMAIN = not listed.

The sentinel `127.255.255.255` is treated as no-data: several RBLs use
it for unauthenticated / lookup-failure cases. Notably
`bl.score.senderscore.com` requires API auth — it's dropped from the
list because public queries always return that sentinel and produced
false-positive HIGH findings.

Sender IP is pulled from the `Received:` chain — the public IP that
hit the receiving MTA. If we can't determine it (ARC-rewritten chain,
weirdly forwarded mail), all RBL findings skip.

Severity tiering — only the three industry-recognized lists trigger
HIGH. UCEPROTECT L2/L3 list whole /24s and ASNs (one bad neighbour
taints everyone) → LOW. Other smaller lists → MEDIUM. This calibrates
the score so a single noisy-RBL hit on a shared ESP IP doesn't swing
the verdict the way a real Spamhaus listing does.

The Finding's wording explicitly tells the reader the listing is on
their email service provider's outbound IP (Brevo, Mailchimp, Klaviyo,
etc.) — not their domain — and the action is to forward the listing
to ESP support. The marketer can't unlist the IP themselves.

v1 cut: 9 lists. Full ~70-list parity is BACKLOG.
"""

from __future__ import annotations

import asyncio
import re

from ...report import Finding
from ...severity import Severity
from ..dns_client import query

# (label, rbl_host, severity_when_listed, human_blurb). Curated from the
# heximcz/mxtoolbox-blacklists list, pruned to lists that are still alive
# in 2026 and actionable. SORBS family removed (decommissioned by
# Proofpoint June 2024, returns NXDOMAIN-everywhere). bl.spamcannibal,
# bl.emailbasura, ix.dnsbl.manitu (NixSPAM) also removed (dead).
# Severity tier mirrors mxtoolbox's "industry standard" weighting.
_RBLS = [
    # ─── Tier 1: industry-standard, drives delivery decisions ────────
    (
        "spamhaus_zen",
        "zen.spamhaus.org",
        Severity.HIGH,
        "Spamhaus ZEN: combined SBL/CSS/XBL/PBL query. Most-consulted reputation list. It directly "
        "hurts inbox placement at Gmail and Outlook.",
    ),
    (
        "spamcop",
        "bl.spamcop.net",
        Severity.HIGH,
        "Spamcop: fed by recipient spam reports. Listings often clear within 24h once the report "
        "flow stops.",
    ),
    (
        "barracuda",
        "b.barracudacentral.org",
        Severity.HIGH,
        "Barracuda Reputation Block List — used by many corporate filters.",
    ),
    (
        "abuseat_cbl",
        "cbl.abuseat.org",
        Severity.HIGH,
        "CBL (Composite Blocking List): botnet and proxy detection, folded into Spamhaus XBL but "
        "still consulted independently.",
    ),
    # ─── Tier 2: medium-impact ───────────────────────────────────────
    (
        "uceprotect_l1",
        "dnsbl-1.uceprotect.net",
        Severity.MEDIUM,
        "UCEPROTECT Level 1 — your specific outbound IP is listed.",
    ),
    ("mailspike_bl", "bl.mailspike.net", Severity.MEDIUM, "Mailspike Block List."),
    ("mailspike_z", "z.mailspike.net", Severity.MEDIUM, "Mailspike Z List — combined reputation."),
    ("psbl", "psbl.surriel.com", Severity.MEDIUM, "PSBL — Passive Spam Block List."),
    (
        "truncate_gbudb",
        "truncate.gbudb.net",
        Severity.MEDIUM,
        "GBUdb Truncate — confirmed senders of substantially-only spam.",
    ),
    (
        "ivmsip",
        "dnsbl.ivmsip.org",
        Severity.MEDIUM,
        "Invaluement IPv4 SIP — paid subscription list; some mid-size receivers consult it.",
    ),
    (
        "backscatterer",
        "ips.backscatterer.org",
        Severity.MEDIUM,
        "Backscatterer — IPs that send mis-directed bounces (backscatter).",
    ),
    (
        "dronebl",
        "dnsbl.dronebl.org",
        Severity.MEDIUM,
        "DroneBL — known compromised drones / bots / proxies.",
    ),
    (
        "blocklistde",
        "bl.blocklist.de",
        Severity.MEDIUM,
        "Blocklist.de — fed by fail2ban / mod_security reports.",
    ),
    ("0spam", "bl.0spam.org", Severity.MEDIUM, "0spam — community reputation list."),
    ("kempt_bl", "spamrbl.imp.ch", Severity.MEDIUM, "imp.ch / KEMPT — Swiss anti-spam project."),
    (
        "sem_black",
        "bl.spameatingmonkey.net",
        Severity.MEDIUM,
        "Spam Eating Monkey Black — automated spam-trap fed list.",
    ),
    ("nordspam_bl", "bl.nordspam.com", Severity.MEDIUM, "Nordspam BL — Nordic spam-trap list."),
    (
        "rats_dyna",
        "dyna.spamrats.com",
        Severity.MEDIUM,
        "SpamRATS Dyna — dynamic IP space being used to send mail.",
    ),
    (
        "rats_noptr",
        "noptr.spamrats.com",
        Severity.MEDIUM,
        "SpamRATS NoPtr — IPs missing PTR records.",
    ),
    (
        "rats_spam",
        "spam.spamrats.com",
        Severity.MEDIUM,
        "SpamRATS Spam — specific spam-source IPs.",
    ),
    (
        "anonmails_dnsbl",
        "spam.dnsbl.anonmails.de",
        Severity.MEDIUM,
        "Anonmails DNSBL — German anti-spam project.",
    ),
    (
        "hostkarma_black",
        "hostkarma.junkemailfilter.com",
        Severity.MEDIUM,
        "Hostkarma: community reputation (note: returns 127.0.0.1 = white, .2 = black, .3 = "
        "yellow).",
    ),
    # ─── Tier 3: noisy / aspirational lists (LOW) ────────────────────
    (
        "uceprotect_l2",
        "dnsbl-2.uceprotect.net",
        Severity.LOW,
        "UCEPROTECT Level 2: the /24 subnet your IP sits in is listed (a noisy neighbour, not "
        "necessarily you).",
    ),
    (
        "uceprotect_l3",
        "dnsbl-3.uceprotect.net",
        Severity.LOW,
        "UCEPROTECT Level 3: your hosting provider's whole network is listed. Rarely actioned by "
        "major receivers.",
    ),
    ("woodys", "blacklist.woody.ch", Severity.LOW, "Woody's SMTP Blacklist."),
    ("dan_torexit", "torexit.dan.me.uk", Severity.LOW, "DAN TorExit — Tor network exit nodes."),
    ("schulte", "rbl.schulte.org", Severity.LOW, "Schulte — small private list."),
    (
        "triumf",
        "rbl2.triumf.ca",
        Severity.LOW,
        "TRIUMF — Canadian particle-physics network anti-spam.",
    ),
    (
        "interserver",
        "rbl.interserver.net",
        Severity.LOW,
        "Interserver RBL — hosting-provider anti-spam list.",
    ),
    (
        "calivent",
        "dnsbl.calivent.com.pe",
        Severity.LOW,
        "Calivent — South American spam-trap list.",
    ),
    ("netherrelays", "relays.nether.net", Severity.LOW, "Nether Relays — open-relay tracking."),
]

# Administrative-error sentinels — NOT real listings. Doc §1 (Spamhaus/
# RFC 5782 prep): 127.255.255.x means the RBL refused our query for an
# administrative reason, not that the IP is bad. Reading any of these
# as "listed" is the #1 false-positive bug in homegrown checkers running
# against public resolvers (8.8.8.8, 1.1.1.1).
#   .252 — typo'd / nonexistent zone
#   .254 — query came from a public/open resolver (Spamhaus, Barracuda)
#   .255 — rate-limited / blocked
# `127.0.0.1` is URIBL/SURBL "Query Refused" sentinel (also Hostkarma's
# whitelist code, which we don't query). Filtered for safety.
_RBL_SENTINELS = frozenset(
    {
        "127.255.255.252",
        "127.255.255.254",
        "127.255.255.255",
        "127.0.0.1",
    }
)

# Per RFC 5782, NXDOMAIN definitively = clean. Anything else (timeout,
# SERVFAIL, no-nameservers) is *unknown* — surface as inconclusive
# rather than wrongly clean.
_INCONCLUSIVE_DNS_ERRORS = frozenset(
    {
        "timeout",
        "no_nameservers",
        "no_answer",
    }
)

_IPV4_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RECEIVED_FROM_RX = re.compile(
    r"from\s+\S+\s*\(.*?\[((?:\d{1,3}\.){3}\d{1,3})\]",
    re.IGNORECASE | re.DOTALL,
)


def _is_public_ipv4(ip: str) -> bool:
    """Reject RFC1918 / loopback / link-local."""
    try:
        parts = [int(p) for p in ip.split(".")]
    except ValueError:
        return False
    if len(parts) != 4:
        return False
    a, b = parts[0], parts[1]
    if a == 10:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 127 or a == 0:
        return False
    if a == 169 and b == 254:
        return False
    return not a >= 224


def extract_sender_ip(headers: dict[str, list[str]]) -> str | None:
    """Walk Received headers (oldest is last; handed-off public IP is at
    the bottom of the chain). Return the first public IPv4 we see scanning
    from oldest-most upward."""
    chain = list(headers.get("received", []))
    if not chain:
        return None
    for hop in reversed(chain):
        m = _RECEIVED_FROM_RX.search(hop)
        if m and _is_public_ipv4(m.group(1)):
            return m.group(1)
        for ip in _IPV4_RX.findall(hop):
            if _is_public_ipv4(ip):
                return ip
    return None


async def _check_one(
    label: str,
    rbl_host: str,
    severity: Severity,
    blurb: str,
    reversed_ip: str,
    sender_ip: str,
) -> Finding:
    qname = f"{reversed_ip}.{rbl_host}"
    ans = await query(qname, "A")
    real_records = [r for r in ans.records if r not in _RBL_SENTINELS] if ans.ok else []
    sentinel_only = bool(ans.records) and not real_records

    # Real listing — non-sentinel A record returned.
    if real_records:
        return Finding(
            check=f"blacklist.{label}",
            severity=severity,
            passed=False,
            message=(
                f"Outbound IP {sender_ip} is listed on {label} ({rbl_host}). "
                f"{blurb} This IP belongs to your email service provider "
                f"(e.g. Brevo, Mailchimp, Klaviyo); listings are usually "
                f"caused by other senders sharing the same IP. To resolve, "
                f"forward this finding to your ESP's deliverability/support "
                f"team — they can request delisting or move you to a "
                f"cleaner IP. You cannot unlist the IP yourself."
            ),
            details={
                "rbl": rbl_host,
                "sender_ip": sender_ip,
                "response": list(ans.records),
                "blurb": blurb,
                "owned_by": "email service provider (ESP outbound IP)",
                "marketer_action": "Forward this finding to your ESP support. They own the IP, not "
                "you.",
            },
        )

    # Definitive clean — RFC 5782 says NXDOMAIN means not listed.
    if ans.error == "nxdomain":
        return Finding(
            check=f"blacklist.{label}",
            severity=Severity.INFO,
            passed=True,
            message=f"Not listed on {label}.",
        )

    # Sentinel-only response: RBL refused our query (open resolver,
    # rate-limit, typo'd zone). Inconclusive — we don't know the IP's
    # status. Surface so user can re-run from a proper resolver.
    if sentinel_only:
        return Finding(
            check=f"blacklist.{label}",
            severity=Severity.INFO,
            passed=False,
            message=(
                f"{label}: lookup refused (sentinel response {ans.records[0]}). "
                "RBL operator returned this because the query came from a "
                "public resolver or hit a rate limit. Re-run from a private "
                "recursive resolver (unbound on 127.0.0.1) for a real result."
            ),
            details={"rbl": rbl_host, "sentinel": list(ans.records)},
        )

    # Timeout / SERVFAIL / no_nameservers / no_answer — unknown, NOT clean.
    # Per the doc, this is the second most-common false-positive trap.
    return Finding(
        check=f"blacklist.{label}",
        severity=Severity.INFO,
        passed=False,
        message=(
            f"{label}: lookup inconclusive ({ans.error}). The RBL did not "
            "respond definitively — could be a transient outage on the "
            "RBL operator's side, a network issue, or DNS misconfiguration. "
            "Re-run shortly."
        ),
        details={"rbl": rbl_host, "dns_error": ans.error},
    )


async def run(headers: dict[str, list[str]]) -> list[Finding]:
    sender_ip = extract_sender_ip(headers)
    if not sender_ip:
        return [
            Finding(
                check="blacklist.sender_ip_extraction",
                severity=Severity.INFO,
                passed=False,
                message="No sender IP recoverable from Received chain; RBL checks skipped.",
            )
        ]

    reversed_ip = ".".join(reversed(sender_ip.split(".")))
    findings = await asyncio.gather(
        *[
            _check_one(label, host, sev, blurb, reversed_ip, sender_ip)
            for label, host, sev, blurb in _RBLS
        ]
    )
    findings.insert(
        0,
        Finding(
            check="blacklist.sender_ip_extraction",
            severity=Severity.INFO,
            passed=True,
            message=f"Sender IP for RBL fan-out: {sender_ip}.",
            details={"ip": sender_ip},
        ),
    )
    return list(findings)
