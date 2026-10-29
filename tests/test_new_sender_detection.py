"""Telling a new sender from one you have seen, without a calendar.

Sendable collects nothing. A user downloads whatever aggregate reports they
happen to have, so a batch is sparse and arbitrary: four files from one week,
or fifty across six months. The old code cut that batch at 21 days back and
used the older part as the baseline, which only works when reports arrive
continuously, the way they did when a service was collecting them.

With no collector, the common batch is a handful of recent reports and the cut
leaves nothing on the older side, so detection switched itself off exactly when
someone was looking.

A DMARC report declares the period it covers. That is the only ordering needed:
a sender present in an earlier period is one you have seen, and one appearing
only in the newest period is new.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from engine.dmarc.parser import AuthResult, DmarcPolicyPublished, DmarcRecord, DmarcReport
from engine.dmarc.window import known_providers_before_latest

DOMAIN = "example.com"
BASE = datetime(2026, 6, 1, tzinfo=UTC)


def _report(offset: int, *ips: str) -> DmarcReport:
    day = BASE + timedelta(days=offset)
    return DmarcReport(
        org_name="google.com",
        report_id=f"d{offset}",
        date_begin=day,
        date_end=day,
        policy=DmarcPolicyPublished(domain=DOMAIN, p="none", adkim="r", aspf="r"),
        records=[
            DmarcRecord(
                source_ip=ip,
                count=5,
                disposition="none",
                policy_dkim="pass",
                policy_spf="pass",
                header_from=DOMAIN,
                auth_dkim=[AuthResult(domain=DOMAIN, result="pass")],
                auth_spf=[AuthResult(domain=DOMAIN, result="pass")],
            )
            for ip in ips
        ],
    )


GOOGLE = "209.85.220.41"
STRANGER = "198.51.100.77"


def test_a_week_of_daily_reports_detects_a_new_sender() -> None:
    """The case the 21 day window got wrong. Seven daily reports all sat inside
    the window, nothing was left for the baseline, and detection switched off."""
    week = [_report(i, GOOGLE) for i in range(6)] + [_report(6, GOOGLE, STRANGER)]
    known = known_providers_before_latest(week)
    assert known is not None, "detection must be on: six earlier days are available"
    stranger_key = _key(STRANGER)
    assert stranger_key not in known
    assert _key(GOOGLE) in known


def test_two_reports_are_enough() -> None:
    known = known_providers_before_latest([_report(0, GOOGLE), _report(1, STRANGER)])
    assert known == {_key(GOOGLE)}


def test_one_report_means_there_is_no_before() -> None:
    """None, not an empty set. An empty set would call every sender brand new."""
    assert known_providers_before_latest([_report(0, GOOGLE)]) is None


def test_several_reports_covering_the_same_single_period() -> None:
    """Two providers reporting the same day is still one period, so still no
    'before'. Yahoo and Google both mailing a report for Monday says nothing
    about what came before Monday."""
    same_day = [_report(0, GOOGLE), _report(0, STRANGER)]
    assert known_providers_before_latest(same_day) is None


def test_reports_from_years_ago_work_the_same_way() -> None:
    """Nothing is measured against today, so age is irrelevant."""
    old = [
        _report(-2000, GOOGLE),
        _report(-1999, GOOGLE),
        _report(-1998, GOOGLE, STRANGER),
    ]
    known = known_providers_before_latest(old)
    assert known == {_key(GOOGLE)}


def test_an_undated_report_cannot_be_a_baseline() -> None:
    """It cannot be shown to come before anything, so it is judged, not trusted."""
    undated = DmarcReport(
        org_name="yahoo.com",
        report_id="undated",
        date_begin=None,
        date_end=None,
        policy=DmarcPolicyPublished(domain=DOMAIN, p="none", adkim="r", aspf="r"),
        records=[],
    )
    assert known_providers_before_latest([undated]) is None


def test_no_reports_at_all() -> None:
    assert known_providers_before_latest([]) is None


def test_the_answer_never_depends_on_when_it_is_run() -> None:
    """Rule 4. Nothing here reads the clock, so the same batch always answers
    the same way, whether the reports are from last week or from 2019."""
    batch = [_report(0, GOOGLE), _report(1, GOOGLE), _report(2, GOOGLE, STRANGER)]
    ancient = [_report(-4000, GOOGLE), _report(-3999, GOOGLE), _report(-3998, GOOGLE, STRANGER)]
    assert known_providers_before_latest(batch) == known_providers_before_latest(ancient)


def _key(ip: str) -> str:
    from engine.dmarc.esp_fingerprint import resolve_identity

    return resolve_identity(
        DmarcRecord(
            source_ip=ip,
            count=1,
            disposition="none",
            policy_dkim="pass",
            policy_spf="pass",
            header_from=DOMAIN,
            auth_dkim=[],
            auth_spf=[],
        )
    ).provider_key
