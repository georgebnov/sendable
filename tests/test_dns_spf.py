"""The SPF record audit: is it published, legal, and within the lookup budget.

SPF is a TXT record naming who may send for a domain. A receiver that cannot
evaluate it treats the mail as unauthenticated, so the failure modes here cost
inbox placement directly.

Every test runs against the `dns` fixture, a zone held in a dict. Any name not
registered answers NXDOMAIN, which is what a real resolver does.
"""

from __future__ import annotations

from engine.domain.dns import spf
from engine.report import Finding
from tests.conftest import FakeDns

PREFIX = "spf_record"


def _by(findings: list[Finding], suffix: str) -> Finding | None:
    for f in findings:
        if f.check == f"{PREFIX}.{suffix}":
            return f
    return None


def _failing(findings: list[Finding]) -> set[str]:
    return {f.check for f in findings if not f.passed}


# ── published or not ───────────────────────────────────────────────────────


async def test_missing_record_is_reported_as_high(dns: FakeDns) -> None:
    findings = await spf.run("example.com")
    published = _by(findings, "published")
    assert published is not None
    assert published.passed is False
    assert published.severity == "HIGH"
    assert published.details["dns_error"] == "nxdomain"


async def test_a_valid_record_passes(dns: FakeDns) -> None:
    dns.set("example.com", "TXT", "v=spf1 include:_spf.google.com ~all")
    findings = await spf.run("example.com")
    published = _by(findings, "published")
    assert published is not None
    assert published.passed is True


async def test_non_spf_txt_records_are_ignored(dns: FakeDns) -> None:
    # A domain's TXT set holds verification strings and DKIM keys too. Only the
    # record starting v=spf1 is an SPF record.
    dns.set(
        "example.com",
        "TXT",
        "google-site-verification=abc123",
        "v=DKIM1; k=rsa; p=MIGf",
        "v=spf1 -all",
    )
    findings = await spf.run("example.com")
    published = _by(findings, "published")
    assert published is not None
    assert published.passed is True
    # The record-count check reports a pass rather than staying silent, so the
    # report says the count was looked at.
    multiple = _by(findings, "multiple_records")
    assert multiple is not None
    assert multiple.passed is True


async def test_a_dns_timeout_is_reported_not_swallowed(dns: FakeDns) -> None:
    # A timeout is not the same as "no record". The finding must say which,
    # because the fix differs: publish a record, or fix the nameserver.
    dns.fail("example.com", "TXT", "timeout")
    findings = await spf.run("example.com")
    published = _by(findings, "published")
    assert published is not None
    assert published.details["dns_error"] == "timeout"


# ── record-level faults ────────────────────────────────────────────────────


async def test_two_spf_records_is_a_permerror(dns: FakeDns) -> None:
    # RFC 7208 section 3.2 forbids this. A receiver returns PermError, which
    # means the domain gets no SPF benefit at all despite publishing twice.
    dns.set("example.com", "TXT", "v=spf1 include:a.example ~all", "v=spf1 include:b.example ~all")
    findings = await spf.run("example.com")
    multiple = _by(findings, "multiple_records")
    assert multiple is not None
    assert multiple.passed is False
    assert multiple.severity == "HIGH"
    assert multiple.details["count"] == 2


async def test_a_ptr_mechanism_is_reported(dns: FakeDns) -> None:
    # ptr is deprecated by RFC 7208 and several receivers ignore or penalise it.
    dns.set("example.com", "TXT", "v=spf1 ptr -all")
    findings = await spf.run("example.com")
    ptr = _by(findings, "ptr_mechanism")
    assert ptr is not None
    assert ptr.passed is False


async def test_text_after_all_is_reported(dns: FakeDns) -> None:
    # Everything after `all` is unreachable, so an include placed there silently
    # does nothing. That is the common cause of "I added my ESP and it still fails".
    dns.set("example.com", "TXT", "v=spf1 -all include:_spf.google.com")
    findings = await spf.run("example.com")
    assert _by(findings, "chars_after_all") is not None


async def test_a_duplicate_include_is_reported(dns: FakeDns) -> None:
    dns.set("example.com", "TXT", "v=spf1 include:a.example include:a.example ~all")
    findings = await spf.run("example.com")
    assert _by(findings, "duplicate_include") is not None


# ── the 10-lookup budget ───────────────────────────────────────────────────


async def test_a_record_inside_the_lookup_budget_passes(dns: FakeDns) -> None:
    dns.set("example.com", "TXT", "v=spf1 include:a.example ~all")
    dns.set("a.example", "TXT", "v=spf1 ip4:198.51.100.0/24 -all")
    findings = await spf.run("example.com")
    lookups = _by(findings, "included_lookups")
    assert lookups is not None
    assert lookups.passed is True


async def test_exceeding_ten_lookups_is_reported(dns: FakeDns) -> None:
    # Over 10 DNS-querying mechanisms, a receiver returns PermError and stops.
    # The domain then has no working SPF even though the record looks complete.
    includes = " ".join(f"include:i{n}.example" for n in range(12))
    dns.set("example.com", "TXT", f"v=spf1 {includes} ~all")
    for n in range(12):
        dns.set(f"i{n}.example", "TXT", "v=spf1 ip4:198.51.100.1 -all")
    findings = await spf.run("example.com")
    lookups = _by(findings, "included_lookups")
    assert lookups is not None
    assert lookups.passed is False


async def test_an_include_that_does_not_resolve_is_a_void_lookup(dns: FakeDns) -> None:
    # RFC 7208 caps void lookups at 2. An include pointing at a dead domain
    # burns budget and returns nothing, which is a silent misconfiguration.
    dns.set(
        "example.com",
        "TXT",
        "v=spf1 include:gone1.example include:gone2.example include:gone3.example ~all",
    )
    findings = await spf.run("example.com")
    void = _by(findings, "void_lookups")
    assert void is not None
    assert void.passed is False


async def test_an_include_loop_terminates(dns: FakeDns) -> None:
    # A record including itself must not hang the audit. Without loop detection
    # this recurses until the lookup budget or the stack runs out.
    dns.set("example.com", "TXT", "v=spf1 include:example.com ~all")
    findings = await spf.run("example.com")
    assert findings, "the check must still return findings on a self-include"


async def test_a_mutual_include_loop_terminates(dns: FakeDns) -> None:
    dns.set("a.example", "TXT", "v=spf1 include:b.example ~all")
    dns.set("b.example", "TXT", "v=spf1 include:a.example ~all")
    findings = await spf.run("a.example")
    assert findings


# ── the check never raises ─────────────────────────────────────────────────


async def test_a_malformed_record_does_not_raise(dns: FakeDns) -> None:
    dns.set("example.com", "TXT", "v=spf1 include: ip4:not-an-ip /// ~all ~all")
    findings = await spf.run("example.com")
    assert findings


async def test_an_empty_record_does_not_raise(dns: FakeDns) -> None:
    dns.set("example.com", "TXT", "v=spf1")
    findings = await spf.run("example.com")
    assert findings
