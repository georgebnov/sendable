"""resolve_identity — composite sender-identity keying (Move A).

Covers the avateq.com report failures this fix targets, plus the
cloud-PTR false-merge guard. PTR is seeded into the module cache so no
test touches the network.
"""

from __future__ import annotations

import pytest

from engine.dmarc import esp_fingerprint as ef
from engine.dmarc.esp_fingerprint import resolve_identity
from engine.dmarc.parser import AuthResult, DmarcRecord


def _seed_ptr(ip: str, host: str | None) -> None:
    """Pin reverse-DNS for `ip` so classify() never hits the network."""
    ef._PTR_CACHE[ip] = host


def _record(ip: str, *, header_from="avateq.com", dkim=(), spf=()) -> DmarcRecord:
    return DmarcRecord(
        source_ip=ip,
        header_from=header_from,
        auth_dkim=[AuthResult(domain=d, result=r) for d, r in dkim],
        auth_spf=[AuthResult(domain=d, result=r) for d, r in spf],
    )


def test_microsoft_ipv6_without_ptr_resolves_via_cidr():
    """The exact avateq case: M365 IPv6 with no PTR was flagged 'unknown
    impostor'. CIDR must name it Microsoft before reverse-DNS is tried."""
    ip = "2603:10b6:a03:2c6::201"
    _seed_ptr(ip, None)  # no PTR, like the real range
    ident = resolve_identity(_record(ip))
    assert ident.name == "Microsoft 365"
    assert ident.kind == "microsoft"
    assert ident.confidence == "cidr"


def test_curated_vendor_ptr_match_wins():
    ip = "198.51.100.7"
    _seed_ptr(ip, "o1.email.kit.com")
    ident = resolve_identity(_record(ip))
    assert ident.name == "Kit (ConvertKit)"
    assert ident.confidence == "ptr_vendor"


def test_unvendored_ptr_clusters_by_registrable_domain():
    """seout6 and its 16 siblings must share ONE provider key so the odd
    one out is 'same known ESP', not a new mystery sender."""
    seout6 = _record("192.99.215.29")
    seout12 = _record("67.215.8.21")
    _seed_ptr("192.99.215.29", "seout6.web-dns1.com")
    _seed_ptr("67.215.8.21", "seout12.web-dns1.com")
    a = resolve_identity(seout6)
    b = resolve_identity(seout12)
    assert a.provider_key == b.provider_key == "web-dns1.com"
    assert a.kind == "infra"


def test_distinct_dkim_domain_beats_cloud_ptr():
    """AWS PTR names the cloud, not the sender. A distinct DKIM d= must
    take over so two tenants don't merge into 'AWS'."""
    ip = "54.227.64.76"
    _seed_ptr(ip, "ec2-54-227-64-76.compute.amazonaws.com")
    ident = resolve_identity(_record(ip, dkim=[("mailer.acme.com", "pass")]))
    assert ident.provider_key == "acme.com"
    assert ident.confidence == "dkim"


def test_cloud_tenants_never_merge():
    """Two different EC2 senders with no distinguishing auth must NOT
    collapse into one identity — they key on their /24, not 'AWS'."""
    _seed_ptr("54.227.64.10", "ec2-54-227-64-10.compute.amazonaws.com")
    _seed_ptr("54.10.0.10", "ec2-54-10-0-10.compute.amazonaws.com")
    a = resolve_identity(_record("54.227.64.10"))
    b = resolve_identity(_record("54.10.0.10"))
    assert a.name == "AWS EC2" and b.name == "AWS EC2"
    assert a.provider_key != b.provider_key  # guarded against false merge
    assert a.kind == "cloud"


def test_aligned_dkim_does_not_become_the_key():
    """A DKIM d= equal to the From domain proves ownership but doesn't
    say which tool sent it — so it must fall through to the infra label,
    not key everything as 'avateq.com'."""
    ip = "192.99.215.30"
    _seed_ptr(ip, "seout9.web-dns1.com")
    ident = resolve_identity(_record(ip, dkim=[("avateq.com", "pass")]))
    assert ident.provider_key == "web-dns1.com"


def test_total_unknown_is_unidentified_not_impostor():
    ip = "45.62.170.230"
    _seed_ptr(ip, None)
    ident = resolve_identity(_record(ip))
    assert ident.name == "unidentified"
    assert ident.kind == "unknown"
    assert ident.provider_key == "45.62.170.0/24"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
