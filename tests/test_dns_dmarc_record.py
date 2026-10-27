"""The DMARC record audit: is one published, is it legal, and does it do anything.

DMARC is a TXT record at `_dmarc.<domain>`. It tells a receiver what to do when a
message claiming the domain fails both SPF and DKIM alignment, and where to send
the daily reports. A domain with no record, or with `p=none` and no `rua=`, gets
neither protection nor visibility.
"""

from __future__ import annotations

from engine.domain.dns import dmarc
from engine.report import Finding
from tests.conftest import FakeDns

PREFIX = "dmarc_record"


def _by(findings: list[Finding], suffix: str) -> Finding | None:
    for f in findings:
        if f.check == f"{PREFIX}.{suffix}":
            return f
    return None


# ── published or not ───────────────────────────────────────────────────────


async def test_a_missing_record_is_reported(dns: FakeDns) -> None:
    published = _by(await dmarc.run("example.com"), "published")
    assert published is not None
    assert published.passed is False


async def test_a_valid_record_passes(dns: FakeDns) -> None:
    dns.set("_dmarc.example.com", "TXT", "v=DMARC1; p=reject; rua=mailto:d@example.com")
    published = _by(await dmarc.run("example.com"), "published")
    assert published is not None
    assert published.passed is True


async def test_a_non_dmarc_txt_record_is_ignored(dns: FakeDns) -> None:
    # The _dmarc name should carry only a DMARC record, but a verification string
    # sometimes lands there. Only a v=DMARC1 record counts.
    dns.set("_dmarc.example.com", "TXT", "google-site-verification=abc123")
    published = _by(await dmarc.run("example.com"), "published")
    assert published is not None
    assert published.passed is False


async def test_two_records_is_a_permerror(dns: FakeDns) -> None:
    # RFC 7489 says a domain with more than one DMARC record has none: receivers
    # cannot choose between them, so the domain gets no protection at all.
    dns.set(
        "_dmarc.example.com",
        "TXT",
        "v=DMARC1; p=reject;",
        "v=DMARC1; p=none;",
    )
    multiple = _by(await dmarc.run("example.com"), "multiple_records")
    assert multiple is not None
    assert multiple.passed is False


# ── the organizational-domain fallback ─────────────────────────────────────


async def test_a_subdomain_inherits_the_parent_record(dns: FakeDns) -> None:
    # RFC 7489 section 6.6.3: with no record at the subdomain, the receiver falls
    # back to the organizational domain. Reporting "no DMARC" for mail.example.com
    # when example.com publishes one would be wrong.
    dns.set("_dmarc.example.com", "TXT", "v=DMARC1; p=reject; rua=mailto:d@example.com")
    findings = await dmarc.run("mail.example.com")
    fallback = _by(findings, "org_domain_fallback")
    assert fallback is not None
    assert fallback.passed is True
    published = _by(findings, "published")
    assert published is not None
    assert published.passed is True


async def test_a_subdomain_with_its_own_record_does_not_fall_back(dns: FakeDns) -> None:
    dns.set("_dmarc.mail.example.com", "TXT", "v=DMARC1; p=reject;")
    dns.set("_dmarc.example.com", "TXT", "v=DMARC1; p=none;")
    findings = await dmarc.run("mail.example.com")
    assert _by(findings, "org_domain_fallback") is None


# ── the policy ─────────────────────────────────────────────────────────────


async def test_a_monitor_only_policy_is_reported_as_doing_nothing(dns: FakeDns) -> None:
    # p=none turns reporting on and changes how no mail is treated. A domain that
    # has sat there for a year is not protected, and should be told so.
    dns.set("_dmarc.example.com", "TXT", "v=DMARC1; p=none; rua=mailto:d@example.com")
    policy = _by(await dmarc.run("example.com"), "policy_enabled")
    assert policy is not None
    assert policy.passed is False


async def test_an_enforcing_policy_passes(dns: FakeDns) -> None:
    dns.set("_dmarc.example.com", "TXT", "v=DMARC1; p=reject; rua=mailto:d@example.com")
    policy = _by(await dmarc.run("example.com"), "policy_enabled")
    assert policy is not None
    assert policy.passed is True


async def test_a_quarantine_policy_passes(dns: FakeDns) -> None:
    dns.set("_dmarc.example.com", "TXT", "v=DMARC1; p=quarantine; rua=mailto:d@example.com")
    policy = _by(await dmarc.run("example.com"), "policy_enabled")
    assert policy is not None
    assert policy.passed is True


# ── syntax ─────────────────────────────────────────────────────────────────


async def test_a_record_with_no_policy_tag_is_a_syntax_error(dns: FakeDns) -> None:
    # p= is required. Without it the record is invalid and receivers ignore it.
    dns.set("_dmarc.example.com", "TXT", "v=DMARC1; rua=mailto:d@example.com")
    syntax = _by(await dmarc.run("example.com"), "syntax")
    assert syntax is not None
    assert syntax.passed is False


async def test_an_unknown_policy_value_is_a_syntax_error(dns: FakeDns) -> None:
    dns.set("_dmarc.example.com", "TXT", "v=DMARC1; p=maybe;")
    syntax = _by(await dmarc.run("example.com"), "syntax")
    assert syntax is not None
    assert syntax.passed is False


# ── external reporting authorisation ───────────────────────────────────────


async def test_reporting_to_another_domain_needs_that_domain_to_agree(
    dns: FakeDns,
) -> None:
    # Sending reports to an address outside the domain requires the receiving
    # domain to publish an authorisation record. Without it, most providers send
    # nothing, and the sender waits for reports that never arrive.
    dns.set("_dmarc.example.com", "TXT", "v=DMARC1; p=none; rua=mailto:d@reports.test")
    external = _by(await dmarc.run("example.com"), "external_validation")
    assert external is not None
    assert external.passed is False


async def test_a_published_authorisation_record_clears_it(dns: FakeDns) -> None:
    dns.set("_dmarc.example.com", "TXT", "v=DMARC1; p=none; rua=mailto:d@reports.test")
    dns.set("example.com._report._dmarc.reports.test", "TXT", "v=DMARC1")
    external = _by(await dmarc.run("example.com"), "external_validation")
    assert external is not None
    assert external.passed is True


async def test_reporting_to_your_own_domain_needs_no_authorisation(
    dns: FakeDns,
) -> None:
    dns.set("_dmarc.example.com", "TXT", "v=DMARC1; p=none; rua=mailto:d@example.com")
    external = _by(await dmarc.run("example.com"), "external_validation")
    assert external is not None
    assert external.passed is True


# ── the check never raises ─────────────────────────────────────────────────


async def test_a_dns_timeout_is_reported_not_swallowed(dns: FakeDns) -> None:
    dns.fail("_dmarc.example.com", "TXT", "timeout")
    findings = await dmarc.run("example.com")
    assert findings


async def test_a_malformed_record_does_not_raise(dns: FakeDns) -> None:
    dns.set("_dmarc.example.com", "TXT", "v=DMARC1;;;p=;rua=;;garbage")
    assert await dmarc.run("example.com")


# ── report addresses: each one is a URI, not a bare address ────────────────


async def test_two_report_addresses_each_with_a_scheme_is_fine(dns: FakeDns) -> None:
    dns.set(
        "_dmarc.example.com",
        "TXT",
        "v=DMARC1; p=reject; rua=mailto:a@example.com,mailto:b@example.com",
    )
    syntax = _by(await dmarc.run("example.com"), "report_uri_syntax")
    assert syntax is not None
    assert syntax.passed is True


async def test_a_report_address_without_mailto_is_reported(dns: FakeDns) -> None:
    """RFC 7489 §6.3: `rua` is a comma-separated list of URIs, not of addresses.

    An entry with no scheme is not a URI. Receivers discard it, and some discard
    the whole tag, so the sender can end up with no reports while the record
    looks right to them. The tool used to strip `mailto:` when present and take
    the address when it was absent, which told the sender their record was fine.
    """
    dns.set(
        "_dmarc.example.com",
        "TXT",
        "v=DMARC1; p=reject; rua=mailto:a@example.com,b@vendor.example",
    )
    findings = await dmarc.run("example.com")

    syntax = _by(findings, "report_uri_syntax")
    assert syntax is not None
    assert syntax.passed is False
    assert "b@vendor.example" in syntax.message
    # The message has to carry the fix, not just the complaint (rule 9).
    assert "mailto:" in syntax.message
    assert syntax.details["malformed"] == ["b@vendor.example"]

    # And the malformed entry is not a destination, so it is not looked up as one.
    external = _by(findings, "external_validation")
    assert external is not None
    assert "vendor.example" not in str(external.details)


async def test_a_record_with_no_rua_skips_the_uri_check(dns: FakeDns) -> None:
    dns.set("_dmarc.example.com", "TXT", "v=DMARC1; p=reject")
    syntax = _by(await dmarc.run("example.com"), "report_uri_syntax")
    assert syntax is not None
    assert syntax.passed is True
