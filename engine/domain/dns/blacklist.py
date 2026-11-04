"""IP RBL fan-out keyed on the sender's outbound public IP.

Standard RBL query: `<reversed-octets>.<rbl-host>` resolved as A. Each list
also gets its test address in the same audit, and `list_reading.py` reads the
pair: an answer in the listing range = listed, NXDOMAIN after a passed test =
not listed, and anything else = not checked. All the lists that were not checked
share 1 finding, `blacklist.unverified`.

`bl.score.senderscore.com` requires API auth. It's dropped from the list because
public queries always return a refusal and produced false-positive HIGH findings.

Sender IP is pulled from the `Received:` chain — the public IP that
hit the receiving MTA. If we can't determine it (ARC-rewritten chain,
weirdly forwarded mail), all RBL findings skip.

Severity tiering — only the four industry-recognized lists trigger
HIGH. UCEPROTECT L2/L3 list whole /24s and ASNs (one bad neighbour
taints everyone) → LOW, with the small or noisy lists in Tier 3 below.
The rest → MEDIUM. This calibrates
the score so a single noisy-RBL hit on a shared ESP IP doesn't swing
the verdict the way a real Spamhaus listing does.

The Finding's wording explicitly tells the reader the listing is on
their email service provider's outbound IP (Brevo, Mailchimp, Klaviyo,
etc.) — not their domain — and the action is to forward the listing
to ESP support. The marketer can't unlist the IP themselves.
"""

from __future__ import annotations

import asyncio
import re

from ...report import Finding
from ...severity import Severity
from ..dns_client import DnsAnswer, query
from .list_reading import (
    Reading,
    has_listing_code,
    not_checked,
    read_answer,
    unverified_finding,
)

# (label, rbl_host, severity_when_listed, human_blurb). Curated from the
# heximcz/mxtoolbox-blacklists list, pruned to lists that are still alive
# in 2026 and actionable. SORBS family removed (decommissioned by
# Proofpoint June 2024, returns NXDOMAIN-everywhere). bl.spamcannibal,
# bl.emailbasura, ix.dnsbl.manitu (NixSPAM) also removed (dead).
# Severity tier mirrors mxtoolbox's "industry standard" weighting.
#
# On 2026-11-04 these lists gave no usable public answer to their test address, so
# they could never report clean, and they are removed: spamrbl.imp.ch,
# blacklist.woody.ch, dnsbl.calivent.com.pe, dnsbl.ivmsip.org, rbl2.triumf.ca,
# relays.nether.net, dyna.spamrats.com, noptr.spamrats.com, spam.spamrats.com.
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
        "Barracuda Reputation Block List: used by many corporate filters.",
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
        "UCEPROTECT Level 1: your specific outbound IP is listed.",
    ),
    ("mailspike_bl", "bl.mailspike.net", Severity.MEDIUM, "Mailspike Block List."),
    ("mailspike_z", "z.mailspike.net", Severity.MEDIUM, "Mailspike Z List: combined reputation."),
    ("psbl", "psbl.surriel.com", Severity.MEDIUM, "PSBL: Passive Spam Block List."),
    (
        "truncate_gbudb",
        "truncate.gbudb.net",
        Severity.MEDIUM,
        "GBUdb Truncate: confirmed senders of substantially-only spam.",
    ),
    (
        "backscatterer",
        "ips.backscatterer.org",
        Severity.MEDIUM,
        "Backscatterer: IPs that send mis-directed bounces (backscatter).",
    ),
    (
        "dronebl",
        "dnsbl.dronebl.org",
        Severity.MEDIUM,
        "DroneBL: known compromised drones / bots / proxies.",
    ),
    (
        "blocklistde",
        "bl.blocklist.de",
        Severity.MEDIUM,
        "Blocklist.de: fed by fail2ban / mod_security reports.",
    ),
    ("0spam", "bl.0spam.org", Severity.MEDIUM, "0spam: community reputation list."),
    (
        "sem_black",
        "bl.spameatingmonkey.net",
        Severity.MEDIUM,
        "Spam Eating Monkey Black: automated spam-trap fed list.",
    ),
    ("nordspam_bl", "bl.nordspam.com", Severity.MEDIUM, "Nordspam BL: Nordic spam-trap list."),
    (
        "anonmails_dnsbl",
        "spam.dnsbl.anonmails.de",
        Severity.MEDIUM,
        "Anonmails DNSBL: German anti-spam project.",
    ),
    (
        "hostkarma_black",
        "hostkarma.junkemailfilter.com",
        Severity.MEDIUM,
        "Hostkarma: sources that send only spam.",
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
    ("dan_torexit", "torexit.dan.me.uk", Severity.LOW, "DAN TorExit: Tor network exit nodes."),
    ("schulte", "rbl.schulte.org", Severity.LOW, "Schulte: small private list."),
    (
        "interserver",
        "rbl.interserver.net",
        Severity.LOW,
        "Interserver RBL: hosting-provider anti-spam list.",
    ),
]

# The test answer of each list is a listing code, with 1 exception: DroneBL
# answers its test address with 127.0.0.1, which reads as a refusal everywhere
# else. It counts for this test only, and never as a listing of a sender.
_LOOPBACK_TEST_ANSWER_LIST = "dnsbl.dronebl.org"

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


def _test_passed(rbl_host: str, test: DnsAnswer) -> bool:
    if has_listing_code(test, rbl_host):
        return True
    return rbl_host == _LOOPBACK_TEST_ANSWER_LIST and "127.0.0.1" in test.records


async def _check_one(
    label: str,
    rbl_host: str,
    severity: Severity,
    blurb: str,
    reversed_ip: str,
    sender_ip: str,
) -> Finding | dict[str, str]:
    """The finding for 1 list, or its `not_checked` row when it gave no usable answer."""
    test, ans = await asyncio.gather(
        query(f"2.0.0.127.{rbl_host}", "A"),
        query(f"{reversed_ip}.{rbl_host}", "A"),
    )
    test_passed = _test_passed(rbl_host, test)
    reading = read_answer(ans, rbl_host, test_passed=test_passed)

    if reading is Reading.LISTED:
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
                f"team: they can request delisting or move you to a "
                f"cleaner IP. You cannot unlist the IP yourself."
            ),
            details={
                "rbl": rbl_host,
                "sender_ip": sender_ip,
                "response": list(ans.records),
                "test_passed": test_passed,
                "blurb": blurb,
                "owned_by": "email service provider (ESP outbound IP)",
                "marketer_action": "Forward this finding to your ESP support. They own the IP, not "
                "you.",
            },
        )

    if reading is Reading.CLEAN:
        return Finding(
            check=f"blacklist.{label}",
            severity=Severity.INFO,
            passed=True,
            message=f"Not listed on {label}.",
        )

    return not_checked(rbl_host, sender_ip, ans)


async def run(headers: dict[str, list[str]]) -> list[Finding]:
    sender_ip = extract_sender_ip(headers)
    if not sender_ip:
        return [
            Finding(
                check="blacklist.sender_ip_extraction",
                severity=Severity.INFO,
                passed=False,
                message=(
                    "This message shows no public IPv4 sending address, so the blocklist "
                    "checks did not run. A draft has none: audit a copy of the message as "
                    "it arrived. Mail sent over IPv6 cannot be checked here, because these "
                    "lists are asked about IPv4 addresses only."
                ),
            )
        ]

    reversed_ip = ".".join(reversed(sender_ip.split(".")))
    results = await asyncio.gather(
        *[
            _check_one(label, host, sev, blurb, reversed_ip, sender_ip)
            for label, host, sev, blurb in _RBLS
        ]
    )
    findings = [
        Finding(
            check="blacklist.sender_ip_extraction",
            severity=Severity.INFO,
            passed=True,
            message=f"Sending address for the blocklist checks: {sender_ip}.",
            details={"ip": sender_ip},
        ),
        *[result for result in results if isinstance(result, Finding)],
    ]
    unchecked = [result for result in results if not isinstance(result, Finding)]
    if unchecked:
        findings.append(
            unverified_finding(
                "blacklist.unverified", unchecked, len(_RBLS), "your sending address"
            )
        )
    return findings
