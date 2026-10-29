"""Thin async-friendly wrapper around the DNS client.

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

from ..dnswire import DnsError, resolve, reverse_name

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


def _classify_error(exc: BaseException) -> str:
    if isinstance(exc, DnsError):
        return exc.category
    return f"error:{type(exc).__name__}"


def _query_sync(name: str, rdtype: str) -> DnsAnswer:
    cache_key = (rdtype.upper(), name.lower().rstrip("."))
    cached = _cache.get(cache_key)
    now = time.monotonic()
    if cached is not None and (now - cached[0]) < _CACHE_TTL:
        return cached[1]

    started = time.monotonic()
    try:
        records = resolve(name, rdtype, timeout=_DEFAULT_TIMEOUT)
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
    """Async wrapper. The client is synchronous, and a thread per lookup keeps
    it that way without an event loop of its own."""
    return await asyncio.to_thread(_query_sync, name, rdtype)


async def query_many(targets: Iterable[tuple[str, str]]) -> list[DnsAnswer]:
    return await asyncio.gather(*(query(name, rdtype) for name, rdtype in targets))


async def reverse_lookup(ip: str) -> DnsAnswer:
    """PTR lookup for an IPv4/IPv6 address."""
    try:
        ptr_name = reverse_name(ip)
    except ValueError:
        return DnsAnswer(
            rdtype="PTR",
            name=ip,
            records=(),
            error="bad_ip",
            elapsed_ms=0,
        )
    return await query(ptr_name, "PTR")
