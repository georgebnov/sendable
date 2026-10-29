"""Source-IP → ESP/cloud-provider classifier (no LLM).

Used by the DMARC classifier to decide whether a "new sending IP"
should fire HIGH ("potential spoofing") or MEDIUM advisory ("new
legitimate sender, add to SPF"). Without this distinction every new
ESP IP in a report would alarm — wrong outcome, since ESPs rotate
IPs constantly inside published ranges.

Strategy (fast → slow):

  1. **Hostname suffix table** — reverse-DNS the IP, then match the
     PTR against a frozen table of vendor-owned domain suffixes. ~95%
     of real ESP traffic resolves cleanly to a recognisable hostname
     (e.g. `mail-by2nam11hn1234.outbound.protection.outlook.com` →
     Microsoft 365).
  2. **No-PTR fallback** — when reverse DNS returns nothing (some
     spoofers / fresh cloud instances), the kind defaults to
     `unknown` and the classifier escalates to HIGH.

PTR results are cached in-process. Pure stdlib (`socket.gethostbyaddr`)
so no extra dep. The lookup runs in a thread when called from async
code so it doesn't block the event loop.

One output every caller needs:
    classify(ip) → ESPMatch{name, kind, hostname}
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Literal

from ..copywriting.link_quality import _registrable
from .parser import DmarcRecord

# The kinds an identity can carry. Named once so _SUFFIX_TABLE and
# ESPMatch.kind cannot drift apart.
ESPKind = Literal["esp", "gateway", "cloud", "microsoft", "google", "isp", "unknown"]

_PTR_CACHE: dict[str, str | None] = {}


# Suffix patterns — order matters (most specific first when multiple
# would match). Each tuple = (hostname suffix, vendor name, kind).
#
# kinds:
#   esp       — legitimate marketing/transactional ESP (Mailchimp, Kit, etc.)
#   gateway   — receiver-side relay / security gateway (Avanan, Mimecast)
#   cloud     — generic IaaS (AWS, GCP, Azure non-M365)
#   microsoft — Microsoft 365 / Office 365 sending infrastructure
#   google    — Google Workspace
#   isp       — ISP / consumer mail (gmail.com inbox-side, etc.)
_SUFFIX_TABLE: tuple[tuple[str, str, ESPKind], ...] = (
    # Microsoft 365 (must come before generic Azure).
    (".outbound.protection.outlook.com", "Microsoft 365", "microsoft"),
    (".protection.outlook.com", "Microsoft 365", "microsoft"),
    (".prod.outlook.com", "Microsoft 365", "microsoft"),
    (".prod.exchangelabs.com", "Microsoft 365", "microsoft"),
    ("mail.protection.outlook.com", "Microsoft 365", "microsoft"),
    # Google Workspace.
    (".google.com", "Google Workspace", "google"),
    (".googlemail.com", "Google Workspace", "google"),
    (".gmail.com", "Google Workspace", "google"),
    (".bh.googleusercontent.com", "Google Cloud", "cloud"),
    (".googleusercontent.com", "Google Cloud", "cloud"),
    (".1e100.net", "Google", "google"),
    # Real ESPs (marketing / transactional).
    (".kit.com", "Kit (ConvertKit)", "esp"),
    (".convertkit.com", "Kit (ConvertKit)", "esp"),
    (".convertkit-mail.com", "Kit (ConvertKit)", "esp"),
    (".convertkit-mail2.com", "Kit (ConvertKit)", "esp"),
    (".sender-sib.com", "Brevo (Sendinblue)", "esp"),
    (".sendinblue.com", "Brevo (Sendinblue)", "esp"),
    (".sendgrid.net", "SendGrid", "esp"),
    (".sendgrid.info", "SendGrid", "esp"),
    (".mailgun.org", "Mailgun", "esp"),
    (".mailgun.net", "Mailgun", "esp"),
    (".mandrillapp.com", "Mandrill (Mailchimp)", "esp"),
    (".rsgsv.net", "Mailchimp", "esp"),
    (".mcsv.net", "Mailchimp", "esp"),
    (".mcdlv.net", "Mailchimp", "esp"),
    (".klaviyomail.com", "Klaviyo", "esp"),
    (".klaviyo.com", "Klaviyo", "esp"),
    (".hubspotemail.net", "HubSpot", "esp"),
    (".hsemail.com", "HubSpot", "esp"),
    (".hubspot.com", "HubSpot", "esp"),
    (".ccsend.com", "Constant Contact", "esp"),
    (".constantcontact.com", "Constant Contact", "esp"),
    (".postmarkapp.com", "Postmark", "esp"),
    (".pmta.com", "PowerMTA", "esp"),
    (".activehosted.com", "ActiveCampaign", "esp"),
    (".amazonses.com", "Amazon SES", "esp"),
    # Receiver-side security / relay gateways. These IPs appear in
    # DMARC reports when the gateway re-relays mail to its protected
    # recipient — often breaks DKIM, but it's the recipient's setup
    # (not yours).
    (".cpmails.com", "Avanan (Check Point)", "gateway"),
    (".cloud-sec-av.com", "Avanan (Check Point)", "gateway"),
    (".avanan.net", "Avanan (Check Point)", "gateway"),
    (".perception-point.io", "Perception Point", "gateway"),
    (".mimecast.com", "Mimecast", "gateway"),
    (".mimecast.org", "Mimecast", "gateway"),
    (".forcepoint.com", "Forcepoint", "gateway"),
    (".forcepoint.net", "Forcepoint", "gateway"),
    (".iphmx.com", "Cisco IronPort", "gateway"),
    (".pphosted.com", "Proofpoint", "gateway"),
    (".barracudanetworks.com", "Barracuda", "gateway"),
    # Generic cloud (catch after specific products above).
    (".compute.amazonaws.com", "AWS EC2", "cloud"),
    (".amazonaws.com", "AWS", "cloud"),
    (".azure.com", "Azure", "cloud"),
    (".cloudapp.azure.com", "Azure", "cloud"),
    (".cloudapp.net", "Azure", "cloud"),
    (".ovh.net", "OVH", "cloud"),
    (".hetzner.com", "Hetzner", "cloud"),
    (".digitalocean.com", "DigitalOcean", "cloud"),
    (".linode.com", "Linode", "cloud"),
    (".vultr.com", "Vultr", "cloud"),
)


@dataclass
class ESPMatch:
    name: str  # human-readable vendor ("Kit (ConvertKit)")
    kind: ESPKind
    hostname: str | None = None  # reverse-DNS result, when available


def _reverse_dns(ip: str) -> str | None:
    """PTR lookup with a tiny in-process cache. None on failure."""
    if ip in _PTR_CACHE:
        return _PTR_CACHE[ip]
    try:
        host, _aliases, _addrs = socket.gethostbyaddr(ip)
        host = host.lower()
    except (socket.herror, socket.gaierror, OSError):
        host = None
    _PTR_CACHE[ip] = host
    return host


def classify(ip: str) -> ESPMatch:
    """Reverse-DNS + suffix-table match. Returns kind='unknown' when
    PTR yields nothing or no suffix matches."""
    if not ip:
        return ESPMatch(name="unknown", kind="unknown")
    host = _reverse_dns(ip)
    if not host:
        return ESPMatch(name="unknown", kind="unknown", hostname=None)
    for suffix, name, kind in _SUFFIX_TABLE:
        # Match on a label boundary, never on a bare string ending. Reverse DNS
        # is set by whoever rents the IP, so "mail.toolkit.com" is something
        # anyone can publish; a plain endswith("kit.com") accepted it as Kit, and
        # the classifier then reports a spoof as a sender you already use.
        domain = suffix.lstrip(".")
        if host == domain or host.endswith("." + domain):
            return ESPMatch(name=name, kind=kind, hostname=host)
    return ESPMatch(name="unknown", kind="unknown", hostname=host)


# ─────────────────────────────────────────────────────────────────────
# Composite sender identity (Move A of the durable identity fix).
#
# `classify()` above answers "what network is this IP on" from PTR alone.
# That's the weakest signal: PTR is attacker-controllable on rented IPs,
# absent on some big-provider ranges (Microsoft's EOP IPv6 has no PTR),
# and generic on cloud ("ec2-…​.amazonaws.com" names AWS, not the tenant).
#
# `resolve_identity()` builds a *composite* key from strongest → weakest:
#   1. authoritative provider CIDR  (also the ONLY signal for no-PTR M365)
#   2. curated vendor PTR match      (Kit, Avanan, M365-by-hostname…)
#   3. DKIM d= domain that differs from From  (authenticated; what Gmail
#      keys reputation on; survives forwarding)
#   4. SPF / return-path domain      (weaker; breaks on forwarding)
#   5. PTR registrable domain        (infra label for single-ESP hosts)
#   6. generic cloud → name it but key on /24 so tenants never merge
#   7. nothing → unidentified, keyed on /24
#
# The point is memory keyed on *provider*, not IP, without ever merging
# two distinct DKIM identities that merely share a cloud PTR.
# ─────────────────────────────────────────────────────────────────────

# Provider IP ranges. Seeded with the cases PTR misses — chiefly
# Microsoft 365 IPv6, whose EOP ranges frequently publish no PTR (the
# whole reason a "Microsoft" sender shows up as an unknown impostor).
# ponytail: hand-seeded from Microsoft/Google published ranges; expand
# from their SPF include chains / endpoint lists if coverage falls short.
_PROVIDER_CIDRS: tuple[tuple[str, str, str], ...] = (
    ("2603:1000::/24", "Microsoft 365", "microsoft"),
    ("2a01:111:f400::/48", "Microsoft 365", "microsoft"),
    ("40.92.0.0/15", "Microsoft 365", "microsoft"),
    ("40.107.0.0/16", "Microsoft 365", "microsoft"),
    ("52.100.0.0/14", "Microsoft 365", "microsoft"),
    ("104.47.0.0/17", "Microsoft 365", "microsoft"),
    ("209.85.128.0/17", "Google Workspace", "google"),
    ("172.217.0.0/16", "Google Workspace", "google"),
    ("66.102.0.0/20", "Google Workspace", "google"),
    ("64.233.160.0/19", "Google Workspace", "google"),
    ("2607:f8b0::/32", "Google Workspace", "google"),
)
_PROVIDER_NETS = tuple(
    (ipaddress.ip_network(cidr), name, kind) for cidr, name, kind in _PROVIDER_CIDRS
)

# PTR kinds trustworthy enough to name the *sender* directly. 'cloud' is
# excluded on purpose: a generic cloud PTR names infrastructure, not the
# sender, so it must not short-circuit the DKIM/SPF signals below.
_LEGIT_VENDOR_KINDS = frozenset({"esp", "gateway", "microsoft", "google"})


@dataclass
class SenderIdentity:
    """Best available identity for a DMARC record's sending source."""

    provider_key: str  # stable clustering / memory key
    name: str  # human-readable label
    kind: str  # microsoft|google|esp|gateway|cloud|domain|infra|unknown
    confidence: Literal["cidr", "ptr_vendor", "dkim", "spf", "ptr", "cloud_ip", "ip"]
    hostname: str | None = None
    source_ip: str | None = None


def _cidr_lookup(ip: str) -> tuple[str, str] | None:
    """(name, kind) when `ip` falls in a known provider range, else None."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net, name, kind in _PROVIDER_NETS:
        if addr.version == net.version and addr in net:
            return name, kind
    return None


def _ip_block(ip: str) -> str | None:
    """/24 (v4) or /48 (v6) containing `ip` — a last-resort dedupe key
    that keeps unrelated cloud tenants from collapsing into one identity."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    prefix = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def _distinct_domain(results, header_reg: str | None) -> str | None:
    """Registrable domain of an auth result whose domain differs from the
    From domain — i.e. the sending tool's own domain, not just "me".
    Passing results preferred. An aligned domain (== From) is skipped: it
    proves ownership but doesn't distinguish which tool sent the mail."""
    passing = [r.domain for r in results if r.result == "pass" and r.domain]
    others = [r.domain for r in results if r.domain]
    for dom in passing + others:
        reg = _registrable(dom)
        if reg and reg != header_reg:
            return reg
    return None


def resolve_identity(record: DmarcRecord) -> SenderIdentity:
    """Composite provider identity for one DMARC record. Never merges two
    distinct DKIM identities that only share a cloud PTR."""
    ip = record.source_ip
    header_reg = _registrable(record.header_from) if record.header_from else None

    # 1. Authoritative provider CIDR (only signal for no-PTR M365 IPv6).
    cid = _cidr_lookup(ip)
    if cid:
        name, kind = cid
        return SenderIdentity(
            provider_key=name,
            name=name,
            kind=kind,
            confidence="cidr",
            source_ip=ip,
        )

    esp = classify(ip)  # PTR + curated suffix table

    # 2. Curated vendor PTR match (excludes generic cloud — see above).
    if esp.kind in _LEGIT_VENDOR_KINDS:
        return SenderIdentity(
            provider_key=esp.name,
            name=esp.name,
            kind=esp.kind,
            confidence="ptr_vendor",
            hostname=esp.hostname,
            source_ip=ip,
        )

    # 3. DKIM d= that names the sending tool (authenticated, survives fwd).
    dkim_reg = _distinct_domain(record.auth_dkim, header_reg)
    if dkim_reg:
        return SenderIdentity(
            provider_key=dkim_reg,
            name=dkim_reg,
            kind="domain",
            confidence="dkim",
            hostname=esp.hostname,
            source_ip=ip,
        )

    # 4. SPF / return-path domain (weaker; breaks on forwarding).
    spf_reg = _distinct_domain(record.auth_spf, header_reg)
    if spf_reg:
        return SenderIdentity(
            provider_key=spf_reg,
            name=spf_reg,
            kind="domain",
            confidence="spf",
            hostname=esp.hostname,
            source_ip=ip,
        )

    # 5. PTR registrable as an infra label — resolved but un-vendored and
    #    not generic cloud. Names single-ESP hosts like web-dns1.com.
    if esp.kind == "unknown" and esp.hostname:
        reg = _registrable(esp.hostname)
        if reg:
            return SenderIdentity(
                provider_key=reg,
                name=reg,
                kind="infra",
                confidence="ptr",
                hostname=esp.hostname,
                source_ip=ip,
            )

    # 6. Generic cloud: show the infra name, key on /24 so tenants split.
    block = _ip_block(ip)
    if esp.kind == "cloud":
        return SenderIdentity(
            provider_key=block or ip,
            name=esp.name,
            kind="cloud",
            confidence="cloud_ip",
            hostname=esp.hostname,
            source_ip=ip,
        )

    # 7. Nothing resolved.
    return SenderIdentity(
        provider_key=block or ip or "unknown",
        name="unidentified",
        kind="unknown",
        confidence="ip",
        source_ip=ip,
    )
