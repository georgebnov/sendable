"""Thin async-friendly wrapper around dnspython.

Centralizes timeout, error swallowing, and an in-process TTL cache so we
don't fan out the same TXT/MX/A lookup per check during a single audit
run. Process-lifetime cache only — Gmail poller runs as a long-lived
loop and a 1h window keeps repeat sender domains cheap without persisting
DNS state across restarts.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterable
from dataclasses import dataclass

import dns.exception
import dns.resolver
import dns.reversename

_DEFAULT_TIMEOUT = 3.0
_CACHE_TTL = 3600.0


@dataclass(frozen=True)
class DnsAnswer:
    """Outcome of a DNS lookup: either records or a category of failure."""

    rdtype: str
    name: str
    records: tuple[str, ...]
    error: str | None
    elapsed_ms: int

    @property
    def ok(self) -> bool:
        return self.error is None


_cache: dict[tuple[str, str], tuple[float, DnsAnswer]] = {}


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=True)
    r.timeout = _DEFAULT_TIMEOUT
    r.lifetime = _DEFAULT_TIMEOUT
    return r


def _classify_error(exc: BaseException) -> str:
    if isinstance(exc, dns.resolver.NXDOMAIN):
        return "nxdomain"
    if isinstance(exc, dns.resolver.NoAnswer):
        return "no_answer"
    if isinstance(exc, dns.resolver.NoNameservers):
        return "no_nameservers"
    if isinstance(exc, dns.exception.Timeout):
        return "timeout"
    return f"error:{type(exc).__name__}"


def _txt_to_str(rdata) -> str:
    """TXT records arrive as multiple byte-strings concatenated; normalize."""
    parts = []
    for s in rdata.strings:
        parts.append(s.decode("utf-8", errors="replace"))
    return "".join(parts)


def _query_sync(name: str, rdtype: str) -> DnsAnswer:
    cache_key = (rdtype.upper(), name.lower().rstrip("."))
    cached = _cache.get(cache_key)
    now = time.monotonic()
    if cached is not None and (now - cached[0]) < _CACHE_TTL:
        return cached[1]

    r = _resolver()
    started = time.monotonic()
    try:
        ans = r.resolve(name, rdtype, raise_on_no_answer=True, search=False)
        records: list[str] = []
        for rdata in ans:
            if rdtype.upper() == "TXT":
                records.append(_txt_to_str(rdata))
            elif rdtype.upper() == "MX":
                records.append(f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}")
            else:
                records.append(rdata.to_text().rstrip("."))
        out = DnsAnswer(
            rdtype=rdtype.upper(),
            name=name,
            records=tuple(records),
            error=None,
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )
    except BaseException as e:
        out = DnsAnswer(
            rdtype=rdtype.upper(),
            name=name,
            records=(),
            error=_classify_error(e),
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )
    _cache[cache_key] = (now, out)
    return out


async def query(name: str, rdtype: str) -> DnsAnswer:
    """Async wrapper. dnspython has an async API but sync-in-threadpool is
    simpler and avoids resolver-state issues across asyncio loops."""
    return await asyncio.to_thread(_query_sync, name, rdtype)


async def query_many(targets: Iterable[tuple[str, str]]) -> list[DnsAnswer]:
    return await asyncio.gather(*(query(name, rdtype) for name, rdtype in targets))


async def reverse_lookup(ip: str) -> DnsAnswer:
    """PTR lookup for an IPv4/IPv6 address."""
    try:
        ptr_name = dns.reversename.from_address(ip).to_text()
    except Exception:
        return DnsAnswer(
            rdtype="PTR",
            name=ip,
            records=(),
            error="bad_ip",
            elapsed_ms=0,
        )
    return await query(ptr_name, "PTR")
