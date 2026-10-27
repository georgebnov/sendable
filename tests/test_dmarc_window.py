"""Turning a pile of DMARC aggregate reports into one picture of who sends for you.

A DMARC aggregate report is an XML file a receiving provider mails you, listing
every source IP that sent mail claiming to be your domain in one reporting period,
and whether each one authenticated. One report is a snapshot from one receiver.
The question a sender actually has is "across everything I received recently, who
sends for me, which of them are failing, and can I tighten my policy yet".

`build_window` answers that. It groups records by sender, sums volume, takes the
worst case on every flag, and reports how many days of data it has. The policy
engine then reads that Window and decides the next step.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from engine.dmarc.parser import (
    AuthResult,
    DmarcPolicyPublished,
    DmarcRecord,
    DmarcReport,
)
from engine.dmarc.window import build_window, include_for_provider

DOMAIN = "example.com"


def _record(
    ip: str,
    *,
    count: int = 10,
    dkim: str = "pass",
    spf: str = "pass",
    dkim_domain: str | None = DOMAIN,
    spf_domain: str | None = DOMAIN,
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


def _report(*records: DmarcRecord, day: int = 1, policy: str = "none") -> DmarcReport:
    return DmarcReport(
        org_name="google.com",
        report_id=f"r{day}",
        date_begin=datetime(2026, 9, day, tzinfo=UTC),
        date_end=datetime(2026, 9, day, 23, 59, tzinfo=UTC),
        policy=DmarcPolicyPublished(domain=DOMAIN, p=policy, adkim="r", aspf="r"),
        records=list(records),
    )


# ── the empty case ─────────────────────────────────────────────────────────


def test_no_reports_gives_an_empty_window() -> None:
    window = build_window([], domain=DOMAIN)
    assert window.senders == []
    assert window.total_volume == 0
    assert window.days_with_data == 0
    assert window.clean_streak_days == 0


def test_a_report_with_no_records_still_counts_as_a_day_of_data() -> None:
    # A receiver that saw no mail for you still tells you it was watching. That
    # is evidence the reporting pipeline works, which matters before advancing.
    window = build_window([_report()], domain=DOMAIN)
    assert window.senders == []
    assert window.days_with_data == 1


# ── grouping and totals ────────────────────────────────────────────────────


def test_volume_sums_across_reports_for_one_sender() -> None:
    reports = [
        _report(_record("209.85.220.41", count=10), day=1),
        _report(_record("209.85.220.41", count=25), day=2),
    ]
    window = build_window(reports, domain=DOMAIN)
    assert len(window.senders) == 1
    assert window.senders[0].volume == 35
    assert window.total_volume == 35


def test_days_with_data_counts_distinct_days_not_reports() -> None:
    # Several receivers report the same day. Counting reports would overstate how
    # long the sender has been observed, which gates policy advancement.
    reports = [
        _report(_record("1.2.3.4"), day=1),
        _report(_record("1.2.3.4"), day=1),
        _report(_record("1.2.3.4"), day=2),
    ]
    assert build_window(reports, domain=DOMAIN).days_with_data == 2


def test_two_different_sources_stay_separate() -> None:
    reports = [_report(_record("1.2.3.4"), _record("5.6.7.8"), day=1)]
    window = build_window(reports, domain=DOMAIN)
    assert len(window.senders) == 2


def test_many_ips_from_one_provider_collapse_to_one_sender() -> None:
    # Microsoft 365 and Google Workspace send from hundreds of IPs. One row per IP
    # would show the same provider twenty times and bury the real problem.
    reports = [
        _report(
            _record("40.92.1.1", count=5),
            _record("40.92.2.2", count=7),
            _record("40.92.3.3", count=3),
            day=1,
        )
    ]
    window = build_window(reports, domain=DOMAIN)
    names = [s.name for s in window.senders]
    assert len(window.senders) == len(set(names)), f"duplicate sender rows: {names}"


# ── alignment, which is what DMARC actually measures ───────────────────────


def test_a_dkim_signature_on_your_own_domain_counts_as_aligned() -> None:
    reports = [_report(_record("1.2.3.4", dkim="pass", dkim_domain=DOMAIN), day=1)]
    sender = build_window(reports, domain=DOMAIN).senders[0]
    assert sender.dkim_aligned is True
    assert sender.dmarc_aligned is True


def test_a_dkim_signature_on_someone_elses_domain_is_not_aligned() -> None:
    # This is the single most common real failure: the provider signs with its own
    # key, so DKIM passes but does not align, and DMARC fails anyway.
    reports = [_report(_record("1.2.3.4", dkim="pass", dkim_domain="sendgrid.info"), day=1)]
    sender = build_window(reports, domain=DOMAIN).senders[0]
    assert sender.dkim_aligned is False
    assert sender.has_dkim_signature is True


def test_spf_passing_on_a_bounce_domain_is_authenticated_but_not_aligned() -> None:
    reports = [
        _report(
            _record(
                "1.2.3.4", dkim="fail", dkim_domain=None, spf="pass", spf_domain="bounce.esp.net"
            ),
            day=1,
        )
    ]
    sender = build_window(reports, domain=DOMAIN).senders[0]
    assert sender.spf_authpassed is True
    assert sender.spf_aligned is False
    assert sender.dmarc_aligned is False


def test_a_subdomain_spf_domain_still_aligns() -> None:
    reports = [_report(_record("1.2.3.4", spf="pass", spf_domain=f"mail.{DOMAIN}"), day=1)]
    assert build_window(reports, domain=DOMAIN).senders[0].spf_aligned is True


def test_alignment_takes_the_best_case_across_reports() -> None:
    # One receiver may report a failure another did not see. A sender that aligned
    # anywhere is configured correctly, so the flag must not be reset by a later
    # report that happened to catch a forwarded copy.
    reports = [
        _report(_record("1.2.3.4", dkim="fail", dkim_domain=None), day=1),
        _report(_record("1.2.3.4", dkim="pass", dkim_domain=DOMAIN), day=2),
    ]
    assert build_window(reports, domain=DOMAIN).senders[0].dkim_aligned is True


# ── legitimacy, which decides whether policy can advance ───────────────────


def test_an_aligned_sender_is_not_a_blocker() -> None:
    reports = [_report(_record("209.85.220.41"), day=d) for d in (1, 2, 3)]
    window = build_window(reports, domain=DOMAIN)
    assert window.clean_streak_days == window.days_with_data


def test_a_recognised_sender_failing_alignment_blocks_the_clean_streak(
    ptr: Callable[[str, str], None],
) -> None:
    # This is the whole point of the streak. Tightening policy while a real sender
    # fails alignment starts rejecting that sender's own mail.
    #
    # The sender must be recognisable for this to be the blocker case. An unknown
    # IP failing both checks is a spoof, and a spoof does not block: tightening
    # policy is exactly what stops it.
    ptr("198.51.100.7", "o1.sendgrid.net")
    reports = [
        _report(
            _record(
                "198.51.100.7",
                dkim="pass",
                dkim_domain="sendgrid.info",
                spf="pass",
                spf_domain="bounce.sendgrid.net",
            ),
            day=d,
        )
        for d in (1, 2, 3)
    ]
    window = build_window(reports, domain=DOMAIN)
    sender = window.senders[0]
    assert sender.dmarc_aligned is False, "neither check aligned with the From domain"
    assert sender.legitimacy != "suspicious", "a recognised provider is not a spoof"
    assert window.clean_streak_days == 0


def test_an_unknown_source_failing_everything_does_not_block() -> None:
    # A spoof must not hold the policy back. Advancing the policy is the fix for
    # it, so treating it as a blocker would keep the domain open to the attack.
    reports = [
        _report(
            _record("1.2.3.4", dkim="fail", dkim_domain=None, spf="fail", spf_domain=None),
            day=d,
        )
        for d in (1, 2, 3)
    ]
    window = build_window(reports, domain=DOMAIN)
    assert window.senders[0].legitimacy == "suspicious"
    assert window.clean_streak_days == window.days_with_data


def test_a_recognised_provider_is_named_in_the_summary(
    ptr: Callable[[str, str], None],
) -> None:
    # "SendGrid" tells the user where to go. "Unknown source 198.51.100.7" does not.
    ptr("198.51.100.7", "o1.sendgrid.net")
    window = build_window([_report(_record("198.51.100.7"), day=1)], domain=DOMAIN)
    assert window.senders[0].name == "SendGrid"


def test_a_recognised_provider_carries_its_spf_include(
    ptr: Callable[[str, str], None],
) -> None:
    # The include is what the user pastes into DNS, so it must come from the
    # verified map rather than being built from the provider's name.
    ptr("198.51.100.7", "o1.sendgrid.net")
    window = build_window([_report(_record("198.51.100.7"), day=1)], domain=DOMAIN)
    assert window.senders[0].esp_include == "include:sendgrid.net"


# ── the SPF include map ────────────────────────────────────────────────────


def test_a_known_provider_maps_to_its_real_include() -> None:
    assert include_for_provider("Google Workspace") == "include:_spf.google.com"
    assert include_for_provider("Microsoft 365") == "include:spf.protection.outlook.com"
    assert include_for_provider("SendGrid") == "include:sendgrid.net"


def test_an_unknown_provider_returns_nothing_rather_than_a_guess() -> None:
    # A wrong include breaks the sender's mail. Anything not verified must return
    # None so the advice stays text-only instead of handing over a bad record.
    assert include_for_provider("Some Tiny ESP") is None
    assert include_for_provider(None) is None
    assert include_for_provider("") is None


# ── the window never raises on odd input ───────────────────────────────────


def test_a_record_with_no_auth_results_does_not_raise() -> None:
    record = DmarcRecord(source_ip="1.2.3.4", count=1, header_from=DOMAIN)
    window = build_window([_report(record, day=1)], domain=DOMAIN)
    assert len(window.senders) == 1
    assert window.senders[0].dmarc_aligned is False


def test_a_report_with_no_policy_block_does_not_raise() -> None:
    report = DmarcReport(
        org_name="yahoo.com",
        date_begin=datetime(2026, 9, 1, tzinfo=UTC),
        date_end=datetime(2026, 9, 1, tzinfo=UTC),
        policy=None,
        records=[_record("1.2.3.4")],
    )
    assert len(build_window([report], domain=DOMAIN).senders) == 1


def test_a_report_with_no_dates_does_not_raise() -> None:
    report = DmarcReport(org_name="aol.com", records=[_record("1.2.3.4")])
    window = build_window([report], domain=DOMAIN)
    assert window.days_with_data == 0
    assert window.total_volume == 10
