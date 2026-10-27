"""The blocklist fan-out: is this sender's IP or links listed anywhere.

A blocklist, or RBL, answers a DNS query about a reversed IP. An A record means
listed; NXDOMAIN means not. Several lists return a sentinel address to say "query
refused" or "rate limited", and reading that as a listing would tell a clean sender
they are blocked, so sentinels are filtered out.

These checks are why `--offline` exists: they query 31 IP blocklists and 8 URL
blocklists, which is 39 outbound lookups per audit.
"""

from __future__ import annotations

from engine.domain.dns import blacklist, sender_dbl, sending_ip_dns, url_reputation
from engine.parse import parse_eml
from engine.report import Finding
from tests.conftest import FakeDns


def _failing(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if not f.passed]


# ── finding the sending IP ─────────────────────────────────────────────────


def test_the_sending_ip_comes_from_the_received_chain() -> None:
    headers = {
        "received": [
            "from mail.example.com (mail.example.com [93.184.216.34]) by mx.google.com",
            "from internal (internal [10.0.0.1]) by mail.example.com",
        ]
    }
    assert blacklist.extract_sender_ip(headers) == "93.184.216.34"


def test_a_private_address_is_not_taken_as_the_sending_ip() -> None:
    # The oldest hop is often inside the sender's own network. Querying a
    # blocklist about 10.0.0.1 answers nothing useful.
    headers = {"received": ["from internal (internal [10.0.0.1]) by mail.example.com"]}
    assert blacklist.extract_sender_ip(headers) is None


def test_no_received_chain_yields_no_ip() -> None:
    assert blacklist.extract_sender_ip({}) is None


# ── the IP blocklist fan-out ───────────────────────────────────────────────


async def test_an_unlisted_ip_passes_every_list(dns: FakeDns) -> None:
    # Nothing registered, so every lookup answers NXDOMAIN, which is "not listed".
    headers = {"received": ["from mail.example.com (mail.example.com [93.184.216.34]) by mx"]}
    findings = await blacklist.run(headers)
    assert findings
    assert not _failing(findings)


async def test_a_listed_ip_is_reported(dns: FakeDns) -> None:
    # 34.216.184.93 is the reversed form of 93.184.216.34, which is how every
    # blocklist is queried.
    dns.set("34.216.184.93.zen.spamhaus.org", "A", "127.0.0.2")
    headers = {"received": ["from mail.example.com (mail.example.com [93.184.216.34]) by mx"]}
    failing = _failing(await blacklist.run(headers))
    assert failing, "a listing on Spamhaus ZEN must be reported"
    assert any("spamhaus" in f.check for f in failing)


async def test_a_sentinel_response_is_not_read_as_a_listing(dns: FakeDns) -> None:
    # Several lists answer 127.255.255.254 to mean "query refused" or "rate
    # limited", which a residential connection hits often. Reading that as a
    # listing would tell a clean sender they are blocked.
    dns.set("34.216.184.93.zen.spamhaus.org", "A", "127.255.255.254")
    headers = {"received": ["from mail.example.com (mail.example.com [93.184.216.34]) by mx"]}
    spamhaus = [f for f in await blacklist.run(headers) if "spamhaus_zen" in f.check]
    assert spamhaus
    # Reported as inconclusive rather than as a listing: INFO carries no penalty,
    # and the message says the list did not answer rather than that the IP is
    # blocked. "We could not check" and "we checked and it is clean" differ.
    assert spamhaus[0].severity == "INFO"
    message = spamhaus[0].message.lower()
    assert "refused" in message and "sentinel" in message
    # Rule 9: the message says what to do about it, not only what happened.
    assert "resolver" in message


async def test_no_sending_ip_skips_the_fan_out(dns: FakeDns) -> None:
    # It says so rather than staying silent, because "we could not check" and
    # "we checked and it is clean" are different answers. INFO carries no penalty.
    findings = await blacklist.run({})
    assert findings
    assert all(f.severity == "INFO" for f in findings)
    assert len(dns.asked) == 0, "no IP means there is nothing to ask about"


# ── the URL blocklists ─────────────────────────────────────────────────────


async def test_a_clean_link_domain_passes(dns: FakeDns) -> None:
    email = parse_eml(
        b"From: Jane <jane@example.com>\r\nContent-Type: text/html\r\n\r\n"
        b'<html><body><a href="https://example.com/x">Read</a></body></html>'
    )
    assert not _failing(await url_reputation.run(email, "example.com"))


async def test_a_listed_link_domain_is_reported(dns: FakeDns) -> None:
    dns.set("bad.test.dbl.spamhaus.org", "A", "127.0.1.2")
    email = parse_eml(
        b"From: Jane <jane@example.com>\r\nContent-Type: text/html\r\n\r\n"
        b'<html><body><a href="https://bad.test/x">Read</a></body></html>'
    )
    failing = _failing(await url_reputation.run(email, "example.com"))
    assert failing, "a link to a listed domain must be reported"


async def test_an_email_with_no_links_is_not_graded(dns: FakeDns) -> None:
    email = parse_eml(b"From: Jane <jane@example.com>\r\n\r\nNo links here.\r\n")
    findings = await url_reputation.run(email, "example.com")
    assert findings
    assert not _failing(findings)


# ── the sender domain on a domain blocklist ────────────────────────────────


async def test_an_unlisted_sender_domain_passes(dns: FakeDns) -> None:
    assert not _failing(await sender_dbl.run("example.com"))


async def test_a_listed_sender_domain_is_reported(dns: FakeDns) -> None:
    dns.set("example.com.dbl.spamhaus.org", "A", "127.0.1.2")
    assert _failing(await sender_dbl.run("example.com"))


# ── reverse DNS on the sending IP ──────────────────────────────────────────


async def test_a_sending_ip_with_matching_forward_and_reverse_dns_passes(
    dns: FakeDns,
) -> None:
    # A mail server should have a PTR record, and that name should resolve back to
    # the same address. Receivers treat a mismatch as a weak signal.
    dns.set("34.216.184.93.in-addr.arpa", "PTR", "mail.example.com")
    dns.set("mail.example.com", "A", "93.184.216.34")
    headers = {"received": ["from mail.example.com (mail.example.com [93.184.216.34]) by mx"]}
    assert not _failing(await sending_ip_dns.run(headers))


async def test_a_sending_ip_with_no_reverse_dns_is_reported(dns: FakeDns) -> None:
    headers = {"received": ["from mail.example.com (mail.example.com [93.184.216.34]) by mx"]}
    findings = await sending_ip_dns.run(headers)
    assert findings


async def test_no_received_chain_skips_the_reverse_lookup(dns: FakeDns) -> None:
    findings = await sending_ip_dns.run({})
    assert findings
    assert all(f.severity == "INFO" for f in findings), (
        "an unmeasurable signal must not carry a score penalty"
    )


# ── none of them raises ────────────────────────────────────────────────────


async def test_every_lookup_timing_out_does_not_raise(dns: FakeDns) -> None:
    # A blocklist refusing or rate-limiting a residential address is the normal
    # case for this tool's users, so a timeout must never fail the audit.
    headers = {"received": ["from mail.example.com (mail.example.com [93.184.216.34]) by mx"]}
    for host in ("zen.spamhaus.org", "bl.spamcop.net", "dbl.spamhaus.org"):
        dns.fail(f"34.216.184.93.{host}", "A", "timeout")
    assert await blacklist.run(headers)
    assert await sender_dbl.run("example.com")
