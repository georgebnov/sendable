"""The domain-health orchestrator, and the judgements it makes before any check.

Two of its decisions matter more than the checks themselves, because both exist
to stop the tool reporting something the sender cannot act on.

A major ESP always has some IP on a noisy blocklist, so scanning the outbound IP
of a shared pool and reporting a listing blames the marketer for their provider's
neighbours. A managed mail operator owns the inbound server, so every Microsoft
365 customer has the identical "PTR mismatch" by design.

Getting either wrong fills a report with findings nobody can fix, which is the
failure mode this repo's own rules call out.
"""

from __future__ import annotations

import pytest

from engine.domain.runner import (
    _demote_to_info,
    _detect_mail_operator,
    _registrable_from,
    run_domain_health,
)
from engine.parse import ParsedEmail, parse_eml
from engine.report import Finding
from engine.severity import Severity

from .conftest import FakeDns


def _email(from_header: str, *, extra: str = "") -> ParsedEmail:
    raw = (
        f"From: {from_header}\r\nTo: reader@gmail.com\r\n"
        f"Subject: Office hours Saturday\r\n{extra}"
        f"Content-Type: text/plain\r\n\r\nHello.\r\n"
    ).encode()
    return parse_eml(raw)


# ── which domain gets audited ─────────────────────────────────────────


@pytest.mark.parametrize(
    ("from_header", "expected"),
    [
        ("Jane <jane@example.com>", "example.com"),
        # A subdomain audits its registrable apex, because SPF, DKIM and DMARC
        # are published there and a per-subdomain answer would be wrong.
        ("Jane <jane@mail.example.com>", "example.com"),
        ("jane@example.co.uk", "example.co.uk"),
        ("Jane <JANE@EXAMPLE.COM>", "example.com"),
    ],
)
def test_the_registrable_domain_comes_from_the_from_address(
    from_header: str, expected: str
) -> None:
    assert _registrable_from(_email(from_header)) == expected


@pytest.mark.parametrize("from_header", ["Jane", "Jane <not-an-address>", "<@example.com>"])
def test_an_unusable_from_address_yields_no_domain(from_header: str) -> None:
    assert _registrable_from(_email(from_header)) is None


async def test_no_sender_domain_reports_one_finding_rather_than_raising(dns: FakeDns) -> None:
    # Every check downstream needs a domain. The runner says so once and stops,
    # instead of fanning out 35 checks against nothing.
    findings = await run_domain_health(_email("Jane"))
    assert [f.check for f in findings] == ["domain_health.sender_extraction"]
    assert not findings[0].passed
    assert findings[0].severity == "INFO"


# ── the managed mail operator ─────────────────────────────────────────


@pytest.mark.parametrize(
    ("mx", "operator"),
    [
        ("10 example-com.mail.protection.outlook.com.", "Microsoft 365"),
        ("1 aspmx.l.google.com.", "Google Workspace"),
        ("10 example-com.mail.eu.mimecast.com.", "Mimecast"),
        ("10 mx.example.ppe-hosted.com.", "Proofpoint"),
        ("10 in1-smtp.messagingengine.com.", "Fastmail"),
        ("10 mx.zoho.com.", "Zoho Mail"),
        ("10 mx-eu.mail.am0.yahoodns.net.", "Yahoo / AOL"),
    ],
)
async def test_a_managed_operator_is_recognised_from_the_mx_records(
    dns: FakeDns, mx: str, operator: str
) -> None:
    dns.set("example.com", "MX", mx)
    assert await _detect_mail_operator("example.com") == operator


async def test_a_self_hosted_mx_is_not_an_operator(dns: FakeDns) -> None:
    dns.set("example.com", "MX", "10 mail.example.com.")
    assert await _detect_mail_operator("example.com") is None


async def test_no_mx_record_is_not_an_operator(dns: FakeDns) -> None:
    assert await _detect_mail_operator("example.com") is None


async def test_a_dns_failure_is_not_an_operator(dns: FakeDns) -> None:
    # Best effort by design. A timeout must fall through to the normal probe
    # path rather than silently demoting every SMTP finding.
    dns.fail("example.com", "MX", "timeout")
    assert await _detect_mail_operator("example.com") is None


# ── demotion keeps the finding and drops the penalty ──────────────────


def test_demotion_turns_a_failure_into_info_and_names_the_operator() -> None:
    failing = Finding(
        check="smtp.banner",
        severity=Severity.HIGH,
        passed=False,
        message="Banner does not match PTR.",
    )
    out = _demote_to_info([failing], "Microsoft 365")
    assert len(out) == 1
    assert out[0].severity == "INFO"
    assert out[0].passed is False, "the finding stays visible, it just stops scoring"
    assert "[managed by Microsoft 365]" in out[0].message
    assert "Banner does not match PTR." in out[0].message
    assert "nothing to fix here" in out[0].message
    assert out[0].source == "domain_config"


def test_demotion_leaves_a_passing_finding_exactly_as_it_was() -> None:
    passing = Finding(
        check="smtp.open_relay",
        severity=Severity.INFO,
        passed=True,
        message="Rejected the open-relay probe.",
    )
    out = _demote_to_info([passing], "Microsoft 365")
    assert out[0].message == passing.message
    assert out[0].severity == passing.severity


# ── the blocklist scan is skipped on a shared ESP pool ────────────────


async def test_a_detected_esp_skips_the_ip_blocklist_scan(dns: FakeDns) -> None:
    # The Feedback-ID header is one of the high-confidence ESP signals. With it
    # the runner must report why it skipped, not scan 31 blocklists against an
    # address the sender does not own.
    email = _email(
        "Jane <jane@example.com>",
        extra="Feedback-ID: 1:2:3:sendgrid\r\nX-SG-EID: abc\r\n",
    )
    findings = await run_domain_health(email)
    skipped = [f for f in findings if f.check == "blacklist.skipped_esp"]
    assert skipped, "no skip finding, so the scan ran against the ESP's IP"
    assert skipped[0].passed is True
    assert skipped[0].severity == "INFO"
    assert "not to your domain" in skipped[0].message
    assert not [
        f
        for f in findings
        if f.check.startswith("blacklist.") and f.check != "blacklist.skipped_esp"
    ]


async def test_no_esp_runs_the_blocklist_path_instead(dns: FakeDns) -> None:
    findings = await run_domain_health(_email("Jane <jane@example.com>"))
    assert not [f for f in findings if f.check == "blacklist.skipped_esp"]
    assert [f for f in findings if f.check.startswith("blacklist.")], "the scan did not run"
