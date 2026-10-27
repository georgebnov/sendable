"""MTA-STS, TLSRPT, and BIMI: the records beyond SPF, DKIM, and DMARC.

None of the three is required, and an audit must say so rather than reporting
three failures at a sender who has the basics right.

  MTA-STS  tells a sending server to require TLS and a valid certificate when
           delivering to this domain. It is a TXT record plus a policy file
           fetched over HTTPS, so it is the one check here that leaves the machine.
  TLSRPT   asks other servers to report TLS delivery failures to an address.
  BIMI     displays a brand logo beside the message in Gmail and Apple Mail. It
           needs DMARC at enforcement first, which is the useful thing to say
           about it.

The policy fetch is also the one place in a default audit that makes an outbound
HTTP request to a host named by the email under audit, so its guard is tested here
as behaviour rather than left to engine/net.py alone.
"""

from __future__ import annotations

from engine.domain.dns import modern_records
from engine.report import Finding
from tests.conftest import FakeDns


def _by(findings: list[Finding], check: str) -> Finding | None:
    return next((f for f in findings if f.check == check), None)


# ── nothing published ──────────────────────────────────────────────────────


async def test_none_of_the_three_is_treated_as_a_failure(dns: FakeDns) -> None:
    # A sender with correct SPF, DKIM, and DMARC and none of these is in good
    # shape. Reporting three failures would bury the findings that matter.
    findings = await modern_records.run("example.com")
    for check in ("mta_sts.published", "tlsrpt.published", "bimi.published"):
        finding = _by(findings, check)
        assert finding is not None, f"{check} did not run"
        assert finding.severity in ("INFO", "LOW"), f"{check} is {finding.severity}"


# ── MTA-STS ────────────────────────────────────────────────────────────────


async def test_a_published_mta_sts_record_is_recognised(dns: FakeDns) -> None:
    dns.set("_mta-sts.example.com", "TXT", "v=STSv1; id=20260901T000000;")
    published = _by(await modern_records.run("example.com"), "mta_sts.published")
    assert published is not None
    assert published.passed is True


async def test_an_mta_sts_record_without_an_id_is_a_syntax_error(dns: FakeDns) -> None:
    # id= is how a sender signals the policy changed. Without it a cached policy
    # is never refreshed.
    dns.set("_mta-sts.example.com", "TXT", "v=STSv1;")
    syntax = _by(await modern_records.run("example.com"), "mta_sts.syntax")
    assert syntax is not None
    assert syntax.passed is False


async def test_two_mta_sts_records_are_reported(dns: FakeDns) -> None:
    dns.set("_mta-sts.example.com", "TXT", "v=STSv1; id=a;", "v=STSv1; id=b;")
    multiple = _by(await modern_records.run("example.com"), "mta_sts.multiple_records")
    assert multiple is not None
    assert multiple.passed is False


async def test_the_policy_fetch_refuses_a_host_that_resolves_internally(
    dns: FakeDns, monkeypatch
) -> None:
    # The domain comes from the From header of the email under audit, and this
    # fetch runs by default. A host answering on a private or link-local address
    # must never be contacted.
    import socket as socket_module

    dns.set("_mta-sts.example.com", "TXT", "v=STSv1; id=20260901T000000;")
    monkeypatch.setattr(
        socket_module, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("169.254.169.254", 0))]
    )
    fetch = _by(await modern_records.run("example.com"), "mta_sts.policy_fetch")
    assert fetch is not None
    assert "blocked" in str(fetch.details) + fetch.message.lower()


# ── the policy file parser ─────────────────────────────────────────────────


def test_a_valid_policy_parses() -> None:
    kv, issues = modern_records._parse_mta_sts_policy(
        "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n"
    )
    assert kv["mode"] == ["enforce"]
    assert kv["mx"] == ["mail.example.com"]
    assert issues == []


def test_repeated_mx_lines_accumulate() -> None:
    kv, _ = modern_records._parse_mta_sts_policy(
        "version: STSv1\nmode: enforce\nmx: a.example.com\nmx: b.example.com\nmax_age: 1\n"
    )
    assert kv["mx"] == ["a.example.com", "b.example.com"]


def test_a_policy_not_starting_with_the_version_is_reported() -> None:
    _kv, issues = modern_records._parse_mta_sts_policy("mode: enforce\nmx: a.example.com\n")
    assert issues


def test_a_missing_mode_is_reported() -> None:
    _kv, issues = modern_records._parse_mta_sts_policy("version: STSv1\nmx: a.example.com\n")
    assert any("mode" in i for i in issues)


def test_an_unknown_mode_is_reported() -> None:
    _kv, issues = modern_records._parse_mta_sts_policy(
        "version: STSv1\nmode: sometimes\nmx: a.example.com\n"
    )
    assert any("sometimes" in i for i in issues)


def test_a_malformed_line_is_reported_without_quoting_it() -> None:
    # The body came from a host the audited email named, and findings are written
    # to the user's stored report. A cloud metadata listing is exactly a run of
    # colon-less lines.
    _kv, issues = modern_records._parse_mta_sts_policy(
        "version: STSv1\nmode: enforce\nmx: a.example.com\niam/security-credentials/admin\n"
    )
    assert issues
    assert "admin" not in " ".join(issues)


# ── TLSRPT ─────────────────────────────────────────────────────────────────


async def test_a_published_tlsrpt_record_is_recognised(dns: FakeDns) -> None:
    dns.set("_smtp._tls.example.com", "TXT", "v=TLSRPTv1; rua=mailto:tls@example.com")
    published = _by(await modern_records.run("example.com"), "tlsrpt.published")
    assert published is not None
    assert published.passed is True


async def test_a_tlsrpt_record_without_a_destination_is_a_syntax_error(
    dns: FakeDns,
) -> None:
    # rua= is the whole point: without it there is nowhere to send the reports.
    dns.set("_smtp._tls.example.com", "TXT", "v=TLSRPTv1;")
    syntax = _by(await modern_records.run("example.com"), "tlsrpt.syntax")
    assert syntax is not None
    assert syntax.passed is False


async def test_two_tlsrpt_records_are_reported(dns: FakeDns) -> None:
    dns.set(
        "_smtp._tls.example.com",
        "TXT",
        "v=TLSRPTv1; rua=mailto:a@example.com",
        "v=TLSRPTv1; rua=mailto:b@example.com",
    )
    multiple = _by(await modern_records.run("example.com"), "tlsrpt.multiple_records")
    assert multiple is not None
    assert multiple.passed is False


# ── BIMI ───────────────────────────────────────────────────────────────────


async def test_bimi_is_not_offered_without_an_enforcing_dmarc_policy(
    dns: FakeDns,
) -> None:
    # BIMI needs DMARC at quarantine or reject. Suggesting a logo record to a
    # domain at p=none sends them to do something that cannot work yet.
    dns.set("_dmarc.example.com", "TXT", "v=DMARC1; p=none;")
    published = _by(await modern_records.run("example.com"), "bimi.published")
    assert published is not None
    # Reported, but at INFO, which carries no score penalty, and the detail says
    # why: the domain is not eligible yet.
    assert published.severity == "INFO"
    assert published.details["eligible"] is False


async def test_a_published_bimi_record_is_recognised(dns: FakeDns) -> None:
    dns.set("_dmarc.example.com", "TXT", "v=DMARC1; p=reject;")
    dns.set("default._bimi.example.com", "TXT", "v=BIMI1; l=https://example.com/logo.svg;")
    published = _by(await modern_records.run("example.com"), "bimi.published")
    assert published is not None
    assert published.passed is True


async def test_a_bimi_record_with_no_logo_is_a_syntax_error(dns: FakeDns) -> None:
    dns.set("_dmarc.example.com", "TXT", "v=DMARC1; p=reject;")
    dns.set("default._bimi.example.com", "TXT", "v=BIMI1;")
    syntax = _by(await modern_records.run("example.com"), "bimi.syntax")
    assert syntax is not None
    assert syntax.passed is False


# ── the check never raises ─────────────────────────────────────────────────


async def test_a_dns_failure_on_every_name_does_not_raise(dns: FakeDns) -> None:
    for name in ("_mta-sts.example.com", "_smtp._tls.example.com", "default._bimi.example.com"):
        dns.fail(name, "TXT", "timeout")
    assert await modern_records.run("example.com")


async def test_malformed_records_everywhere_do_not_raise(dns: FakeDns) -> None:
    dns.set("_mta-sts.example.com", "TXT", "garbage;;;")
    dns.set("_smtp._tls.example.com", "TXT", "v=TLSRPTv1;;;;")
    dns.set("default._bimi.example.com", "TXT", "v=BIMI1;;;l=;;a=")
    assert await modern_records.run("example.com")
