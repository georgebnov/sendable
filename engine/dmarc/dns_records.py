"""Live DNS reads for SPF + DMARC records on a user's domain.

Caches per (domain) for 24h in process memory — DMARC reports are once-daily
so faster cache invalidation doesn't help. Wrapped to never raise: on any
DNS failure we return 'no record' (the policy_engine treats missing as the
ACTION case anyway).
"""

from __future__ import annotations

import re
import time

from engine.dmarc.policy_engine import DmarcRecord, SpfRecord
from engine.dmarc.spf_parser import parse as parse_spf

from ..dnswire import DnsError, resolve

_CACHE_TTL_SECONDS = 24 * 60 * 60
_SPF_PREFIX_RX = re.compile(r"^\s*v\s*=\s*spf1\b", re.IGNORECASE)
_DMARC_PREFIX_RX = re.compile(r"^\s*v\s*=\s*DMARC1\b", re.IGNORECASE)

# {domain: (timestamp, SpfRecord)} and {domain: (timestamp, DmarcRecord)}
_spf_cache: dict[str, tuple[float, SpfRecord]] = {}
_dmarc_cache: dict[str, tuple[float, DmarcRecord]] = {}


def _now() -> float:
    return time.time()


def _query_txt(name: str) -> list[str]:
    """One TXT lookup. Returns an empty list on any failure.

    The resolver already joins the pieces of a split record and hands back the
    value itself, so there is no quoting to undo here. Undoing it was also
    wrong for a record that legitimately contains a quotation mark.
    """
    try:
        return resolve(name, "TXT", timeout=5)
    except DnsError:
        return []


# ─── SPF ──────────────────────────────────────────────────────────────
def read_spf(domain: str) -> SpfRecord:
    cached = _spf_cache.get(domain)
    if cached and (_now() - cached[0] < _CACHE_TTL_SECONDS):
        return cached[1]

    records = [r for r in _query_txt(domain) if _SPF_PREFIX_RX.match(r)]
    result = parse_spf(records)
    _spf_cache[domain] = (_now(), result)
    return result


# ─── DMARC ────────────────────────────────────────────────────────────
def _parse_dmarc_txt(raw: str) -> DmarcRecord:
    """Convert a v=DMARC1 TXT body into a DmarcRecord."""
    kv: dict[str, str] = {}
    for pair in raw.split(";"):
        pair = pair.strip()
        if "=" not in pair:
            continue
        k, v = pair.split("=", 1)
        kv[k.strip().lower()] = v.strip()
    try:
        pct = int(kv.get("pct", "100"))
    except ValueError:
        pct = 100
    return DmarcRecord(
        exists=True,
        p=kv.get("p", "").lower(),
        sp=kv.get("sp"),
        pct=pct,
        adkim=kv.get("adkim", "r").lower(),
        aspf=kv.get("aspf", "r").lower(),
    )


def read_dmarc(domain: str) -> DmarcRecord:
    cached = _dmarc_cache.get(domain)
    if cached and (_now() - cached[0] < _CACHE_TTL_SECONDS):
        return cached[1]

    records = [r for r in _query_txt(f"_dmarc.{domain}") if _DMARC_PREFIX_RX.match(r)]
    result = DmarcRecord(exists=False) if not records else _parse_dmarc_txt(records[0])
    _dmarc_cache[domain] = (_now(), result)
    return result
