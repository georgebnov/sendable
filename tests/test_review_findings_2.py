"""Regressions for the defects the second review round found.

Five of them sit in the DMARC summary, which is what decides whether a sender is
told it is safe to tighten their policy. Getting that wrong either tells someone
to publish a policy that rejects their own mail, or tells them a spoofer is one of
their own senders.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from engine.dmarc.parser import (
    AuthResult,
    DmarcPolicyPublished,
    DmarcRecord,
    DmarcReport,
)
from engine.dmarc.policy_engine import _build_record
from engine.dmarc.summary import _aligned, _forwarder_domain, summarise_reports

DOMAIN = "example.com"


def _rec(
    ip: str = "209.85.220.41",
    *,
    count: int = 100,
    dkim_domain: str | None = DOMAIN,
    spf_domain: str | None = DOMAIN,
    dkim: str = "pass",
    spf: str = "pass",
    disposition: str = "none",
) -> DmarcRecord:
    return DmarcRecord(
        source_ip=ip,
        count=count,
        disposition=disposition,
        policy_dkim=dkim,
        policy_spf=spf,
        header_from=DOMAIN,
        auth_dkim=[AuthResult(domain=dkim_domain, result=dkim)] if dkim_domain else [],
        auth_spf=[AuthResult(domain=spf_domain, result=spf)] if spf_domain else [],
    )


def _report(*records: DmarcRecord, day: int = 1, adkim: str = "r", aspf: str = "r") -> DmarcReport:
    return DmarcReport(
        org_name="google.com",
        report_id=f"g-{day}",
        date_begin=datetime(2026, 9, day, tzinfo=UTC),
        date_end=datetime(2026, 9, day, 23, 59, tzinfo=UTC),
        policy=DmarcPolicyPublished(domain=DOMAIN, p="none", adkim=adkim, aspf=aspf),
        records=list(records),
    )


# ── alignment must match on a label boundary ───────────────────────────────


@pytest.mark.parametrize("lookalike", ["notexample.com", "evil-example.com", "myexample.com"])
def test_a_lookalike_domain_is_not_spf_aligned(lookalike: str) -> None:
    # A bare endswith accepted any domain ending in the target. A spoofer that
    # passes SPF on a lookalike then read as aligned, dropped out of the blocker
    # list, and the engine offered to ADVANCE the policy.
    assert _aligned([AuthResult(domain=lookalike, result="pass")], DOMAIN, strict=False) is False


@pytest.mark.parametrize("real", ["example.com", "mail.example.com", "em.example.com"])
def test_the_domain_and_its_subdomains_are_spf_aligned(real: str) -> None:
    assert _aligned([AuthResult(domain=real, result="pass")], DOMAIN, strict=False) is True


# ── relaxed alignment is the DMARC default ─────────────────────────────────


def test_a_subdomain_dkim_signature_aligns_under_the_default_policy() -> None:
    # adkim defaults to relaxed, which aligns on the organizational domain. An ESP
    # signing d=em.example.com for From: @example.com is correctly aligned, and
    # calling it unaligned told the user a working sender was failing DMARC and
    # that they must not tighten their policy.
    summary = summarise_reports([_report(_rec(dkim_domain="em.example.com"), day=1)], domain=DOMAIN)
    assert summary.senders[0].dkim_aligned is True


def test_a_strict_policy_requires_an_exact_dkim_match() -> None:
    # adkim=s is published by domains that want exactly this. The tags were parsed
    # and then never read, so a strict domain got relaxed treatment.
    summary = summarise_reports(
        [_report(_rec(dkim_domain="em.example.com"), day=1, adkim="s")], domain=DOMAIN
    )
    assert summary.senders[0].dkim_aligned is False


def test_a_strict_spf_policy_requires_an_exact_match() -> None:
    summary = summarise_reports(
        [_report(_rec(spf_domain="mail.example.com", dkim_domain=None), day=1, aspf="s")],
        domain=DOMAIN,
    )
    assert summary.senders[0].spf_aligned is False


# ── the worst disposition must survive a merge ─────────────────────────────


def test_a_rejection_reported_by_one_receiver_is_not_lost() -> None:
    # policy_engine gates its highest-priority action on a sender being
    # quarantined or rejected right now. absorb() took the worst legitimacy but
    # dropped disposition, so whichever report was read first decided it, and a
    # user whose real mail was being rejected was never told.
    reports = [
        _report(_rec(disposition="none"), day=1),
        _report(_rec(disposition="reject"), day=2),
    ]
    assert summarise_reports(reports, domain=DOMAIN).senders[0].disposition == "reject"
    assert (
        summarise_reports(list(reversed(reports)), domain=DOMAIN).senders[0].disposition == "reject"
    )


# ── the forwarder label is a registrable domain ────────────────────────────


@pytest.mark.parametrize(
    ("spf_domain", "expected"),
    [
        ("mail.forwarder.co.uk", "forwarder.co.uk"),
        ("srs.relay.com.au", "relay.com.au"),
        ("a.b.megamailservers.com", "megamailservers.com"),
    ],
)
def test_the_forwarder_domain_respects_the_public_suffix(spf_domain: str, expected: str) -> None:
    # Taking the last two labels turned every UK, Australian, and Japanese
    # forwarder into "co.uk" or "com.au", collapsing unrelated forwarders into one
    # row, which is the opposite of what the grouping is for.
    record = DmarcRecord(
        source_ip="1.2.3.4", auth_spf=[AuthResult(domain=spf_domain, result="pass")]
    )
    assert _forwarder_domain(record) == expected


def _report_xml(domain: str, day: datetime, source_ip: str = "203.0.113.9") -> bytes:
    """One aggregate report for `domain` covering `day`, as a provider sends it."""
    begin = int(day.timestamp())
    end = int(day.replace(hour=23, minute=59).timestamp())
    return f"""<?xml version="1.0"?>
<feedback>
  <report_metadata><org_name>google.com</org_name>
    <report_id>{domain}-{day:%Y%m%d}</report_id>
    <date_range><begin>{begin}</begin><end>{end}</end></date_range>
  </report_metadata>
  <policy_published><domain>{domain}</domain><p>none</p></policy_published>
  <record><row><source_ip>{source_ip}</source_ip><count>5</count>
      <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
    </row><identifiers><header_from>{domain}</header_from></identifiers>
    <auth_results><spf><domain>attacker.test</domain><result>fail</result></spf></auth_results>
  </record>
</feedback>""".encode()


# ── the record the tool tells you to publish must be valid ─────────────────


def test_the_suggested_record_does_not_double_the_mailto_scheme() -> None:
    # The CLI default already carries the scheme. rua=mailto:mailto:... is not a
    # valid DMARC URI, so receivers drop the tag and stop sending the reports the
    # whole tool runs on.
    record = _build_record("none", 0, "mailto:dmarc@example.com")
    assert "mailto:mailto:" not in record
    assert "rua=mailto:dmarc@example.com" in record


def test_a_bare_address_still_gets_the_scheme() -> None:
    assert "rua=mailto:dmarc@example.com" in _build_record("none", 0, "dmarc@example.com")


# ── a passing check must not be reported as skipped ────────────────────────


def test_draft_mode_keeps_a_required_headers_check_that_already_passed() -> None:
    # The passing finding carries no details["missing"], so the rewrite treated it
    # as an unexpected shape, deleted it, and the advisory then told the user a
    # check that had actually run was unanswerable.
    from engine.draft import DRAFT_ADVISORY, calibrate_for_draft
    from engine.report import Finding
    from engine.severity import Severity

    passing = Finding(
        check="headers.required_headers",
        severity=Severity.INFO,
        passed=True,
        message="All required RFC 5322 headers present.",
    )
    out = calibrate_for_draft([passing])
    kept = [f for f in out if f.check == "headers.required_headers"]
    assert kept, "a check that passed must not be deleted"
    assert kept[0].passed is True
    advisory = next(f for f in out if f.check == DRAFT_ADVISORY)
    assert "headers.required_headers" not in advisory.details["skipped_checks"]


# ── one sender's audits must not be counted against another ────────────────


def test_a_similar_domain_is_not_counted_as_another_sender() -> None:
    # An earlier version matched a filename that rewrote every character outside
    # [a-z0-9.-] to a dash, so "sub_example.com" became "sub-example.com" and was
    # counted against "example.com". The match is exact now.
    from engine.dmarc.parser import parse
    from engine.dmarc.summary import for_domain, pick_domain

    day = datetime(2026, 9, 28, tzinfo=UTC)
    mine = parse(_report_xml("example.com", day))
    theirs = parse(_report_xml("sub_example.com", day))

    def domains(reports) -> list[str]:
        return [r.policy.domain for r in reports if r.policy]

    assert domains(for_domain([mine, theirs], "example.com")) == ["example.com"]
    assert domains(for_domain([mine, theirs], "sub_example.com")) == ["sub_example.com"]
    # Two domains in one batch means the caller has to say which one it meant.
    assert pick_domain([mine, theirs]) is None
    assert pick_domain([mine]) == "example.com"


# ── a failed ingest must not report success ────────────────────────────────


def test_reading_only_unreadable_files_exits_non_zero(tmp_path) -> None:
    # Returning 0 let a caller treat total failure as success. This exits before
    # any DNS read, so the test stays off the network.
    import subprocess
    import sys
    from pathlib import Path

    junk = tmp_path / "not-a-report.xml"
    junk.write_text("<html>this is not a dmarc report</html>")
    root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, str(root / "scripts" / "dmarc.py"), str(junk)],
        capture_output=True,
        text=True,
        cwd=root,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "could be read as a DMARC" in result.stderr


# ── the streak is only safe because evidence depth is gated first ──────────
