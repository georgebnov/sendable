"""RFC 7489 DMARC aggregate-report parser.

Input: bytes of one report (raw XML, or gzipped, or zipped).
Output: DmarcReport dataclass with N child DmarcRecord rows.

The DMARC RUA schema is stable across reporters (Google, Microsoft,
Mimecast, Cisco IronPort, Yahoo, etc.) so a single parser covers
every source. Reports arrive as email attachments, typically
gzipped (.xml.gz) or zipped (.zip containing one .xml); the parser
sniffs the magic bytes and decompresses transparently.

Fields preserved per record (all the ones the
deterministic classifier needs):

  source_ip          — the server that sent the email
  count              — how many emails this row represents
  disposition        — none | quarantine | reject (what receiver did)
  policy_dkim        — pass | fail (alignment result)
  policy_spf         — pass | fail
  header_from        — domain in the From: header
  envelope_from      — bounce-path domain (empty = bounce message)
  envelope_to        — recipient domain (when present)
  auth_dkim          — list of (domain, selector, result) tuples
  auth_spf           — list of (domain, result) tuples
  reasons            — list of (type, comment) override-reasons (ARC,
                       forwarded_email, mailing_list, etc.)

The classifier downstream reads exactly these fields. No
reporter-specific quirks bleed in.
"""

from __future__ import annotations

import gzip
import io
import re
import xml.etree.ElementTree as _stdET  # only for the Element TYPE annotation
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime

# Use defusedxml against XXE + billion-laughs entity expansion. Reports come
# from arbitrary senders on the internet — bare xml.etree is unsafe here.
import defusedxml.ElementTree as ET

# Reporters declare XML namespaces inconsistently — Microsoft, Comcast,
# Mimecast sometimes do; Google + Yahoo don't. Stripping the namespace
# prefix from every tag at parse time means hardcoded findall("record")
# keeps working everywhere.
_NS_RX = re.compile(r"^\{[^}]+\}")


def _strip_ns(elem) -> None:
    """Mutate elem in place: drop XML namespace prefix from every tag in
    the subtree. RFC 7489 reports don't carry semantic namespaces — they're
    a quirk of which tooling wrote the file."""
    for el in elem.iter():
        el.tag = _NS_RX.sub("", el.tag)


# ─── Models ──────────────────────────────────────────────────────────


@dataclass
class AuthResult:
    """One row inside <auth_results>/<dkim> or <auth_results>/<spf>."""

    domain: str | None = None
    selector: str | None = None  # DKIM only
    result: str = "none"  # pass | fail | none | temperror | softfail


@dataclass
class PolicyOverride:
    """One <reason> entry under <policy_evaluated>. Indicates the
    receiver overrode the policy (e.g. ARC chain trusted, forwarded
    email, mailing list)."""

    type: str
    comment: str | None = None


@dataclass
class DmarcRecord:
    """One <record> row inside a DMARC report. ~1 per source-IP-per-
    receiver-per-period combination."""

    source_ip: str
    count: int = 1
    disposition: str = "none"  # none | quarantine | reject
    policy_dkim: str = "none"  # pass | fail
    policy_spf: str = "none"
    header_from: str | None = None
    envelope_from: str | None = None
    envelope_to: str | None = None
    auth_dkim: list[AuthResult] = field(default_factory=list)
    auth_spf: list[AuthResult] = field(default_factory=list)
    reasons: list[PolicyOverride] = field(default_factory=list)


@dataclass
class DmarcPolicyPublished:
    """<policy_published> block — what the reporter saw in your DNS at
    the time of the report."""

    domain: str
    adkim: str | None = None  # r | s
    aspf: str | None = None  # r | s
    p: str | None = None  # none | quarantine | reject
    sp: str | None = None
    pct: int | None = None
    fo: str | None = None


@dataclass
class DmarcReport:
    """One ingested aggregate report. Maps directly onto the
    <feedback> root of the XML."""

    org_name: str | None = None
    org_email: str | None = None
    report_id: str | None = None
    date_begin: datetime | None = None
    date_end: datetime | None = None
    policy: DmarcPolicyPublished | None = None
    records: list[DmarcRecord] = field(default_factory=list)


# ─── Decompression ───────────────────────────────────────────────────


def _decompress(raw: bytes) -> bytes:
    """Return raw XML bytes. Sniffs gzip, zip, or plain XML."""
    if len(raw) < 4:
        return raw
    # Gzip magic.
    if raw[:2] == b"\x1f\x8b":
        return gzip.decompress(raw)
    # Zip magic.
    if raw[:4] == b"PK\x03\x04":
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            xml_name = next(
                (n for n in z.namelist() if n.lower().endswith(".xml")),
                None,
            )
            if xml_name is None:
                raise ValueError("zip archive contains no .xml entry")
            return z.read(xml_name)
    return raw


# ─── XML → models ────────────────────────────────────────────────────


def _text(elem: _stdET.Element | None, tag: str) -> str | None:
    if elem is None:
        return None
    child = elem.find(tag)
    if child is None or child.text is None:
        return None
    val = child.text.strip()
    return val or None


def _parse_metadata(root: _stdET.Element) -> dict:
    meta = root.find("report_metadata")
    if meta is None:
        return {}
    date_range = meta.find("date_range")
    date_begin = _text(date_range, "begin")
    date_end = _text(date_range, "end")
    return {
        "org_name": _text(meta, "org_name"),
        "org_email": _text(meta, "email"),
        "report_id": _text(meta, "report_id"),
        "date_begin": _epoch_to_dt(date_begin),
        "date_end": _epoch_to_dt(date_end),
    }


def _epoch_to_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(int(value), tz=UTC)
    except (ValueError, OSError):
        return None


def _parse_policy(root: _stdET.Element) -> DmarcPolicyPublished | None:
    pol = root.find("policy_published")
    if pol is None:
        return None
    domain = _text(pol, "domain")
    if not domain:
        return None
    pct = _text(pol, "pct")
    try:
        pct_int = int(pct) if pct is not None else None
    except ValueError:
        pct_int = None
    return DmarcPolicyPublished(
        domain=domain,
        adkim=_text(pol, "adkim"),
        aspf=_text(pol, "aspf"),
        p=_text(pol, "p"),
        sp=_text(pol, "sp"),
        pct=pct_int,
        fo=_text(pol, "fo"),
    )


def _parse_record(rec: _stdET.Element) -> DmarcRecord | None:
    row = rec.find("row")
    if row is None:
        return None
    source_ip = _text(row, "source_ip")
    if not source_ip:
        return None
    count_txt = _text(row, "count")
    try:
        count = int(count_txt) if count_txt else 1
    except ValueError:
        count = 1

    pol_eval = row.find("policy_evaluated")
    disposition = _text(pol_eval, "disposition") or "none"
    policy_dkim = _text(pol_eval, "dkim") or "none"
    policy_spf = _text(pol_eval, "spf") or "none"
    reasons: list[PolicyOverride] = []
    if pol_eval is not None:
        for r in pol_eval.findall("reason"):
            t = _text(r, "type")
            if t:
                reasons.append(PolicyOverride(type=t, comment=_text(r, "comment")))

    identifiers = rec.find("identifiers")
    header_from = _text(identifiers, "header_from")
    envelope_to = _text(identifiers, "envelope_to")
    # envelope_from semantics:
    #   - element present with text → return the domain string
    #   - element present but empty/whitespace → "" (NDR bounce marker)
    #   - element missing entirely → None (reporter omitted the field)
    # The classifier reads "" as 'this IS a bounce' and None as 'unknown',
    # so we must distinguish them. The old code treated both as None →
    # nothing ever flagged as bounce; THIS now also fixes the inverse
    # bug we hit where None was being treated as "" by the classifier.
    envelope_from: str | None = None
    if identifiers is not None:
        env_node = identifiers.find("envelope_from")
        if env_node is not None:
            envelope_from = (env_node.text or "").strip()

    auth = rec.find("auth_results")
    auth_dkim: list[AuthResult] = []
    auth_spf: list[AuthResult] = []
    if auth is not None:
        for d in auth.findall("dkim"):
            auth_dkim.append(
                AuthResult(
                    domain=_text(d, "domain"),
                    selector=_text(d, "selector"),
                    result=_text(d, "result") or "none",
                )
            )
        for s in auth.findall("spf"):
            auth_spf.append(
                AuthResult(
                    domain=_text(s, "domain"),
                    result=_text(s, "result") or "none",
                )
            )

    return DmarcRecord(
        source_ip=source_ip,
        count=count,
        disposition=disposition,
        policy_dkim=policy_dkim,
        policy_spf=policy_spf,
        header_from=header_from,
        envelope_from=envelope_from,
        envelope_to=envelope_to,
        auth_dkim=auth_dkim,
        auth_spf=auth_spf,
        reasons=reasons,
    )


def parse(raw: bytes) -> DmarcReport:
    """Parse a single DMARC aggregate report (XML, gzipped XML, or
    zipped XML). Raises ValueError on a structurally invalid feed.

    Uses defusedxml for safety and strips XML namespaces before traversal
    so namespaced reports (Microsoft, Comcast) feed the same findall()
    paths as the un-namespaced ones (Google, Yahoo)."""
    xml_bytes = _decompress(raw)
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as e:
        raise ValueError(f"DMARC XML parse error: {e}") from e
    _strip_ns(root)
    if root.tag != "feedback":
        raise ValueError(f"unexpected root element {root.tag!r}, want <feedback>")
    meta = _parse_metadata(root)
    policy = _parse_policy(root)
    records: list[DmarcRecord] = []
    for rec in root.findall("record"):
        parsed = _parse_record(rec)
        if parsed:
            records.append(parsed)
    return DmarcReport(**meta, policy=policy, records=records)
