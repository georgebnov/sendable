"""The window is measured from the reports, not from today's date.

Sendable keeps nothing between runs, so the files a user passes are the whole
dataset. Measuring a window from the wall clock made the tool second-guess that
choice: hand it last quarter's reports and it refused all of them for being old,
even though they are exactly the reports the user asked about.

Anchoring to the newest report in the batch fixes that and removes a clock
dependency at the same time, which rule 4 wants anyway. The newest report is
always inside its own window, so there is no batch that produces nothing.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from engine.dmarc.parser import DmarcPolicyPublished, DmarcReport
from engine.dmarc.window import split_at_window

DOMAIN = "example.com"


def _report(when: datetime) -> DmarcReport:
    return DmarcReport(
        org_name="google.com",
        report_id=when.date().isoformat(),
        date_begin=when,
        date_end=when,
        policy=DmarcPolicyPublished(domain=DOMAIN, p="none", adkim="r", aspf="r"),
        records=[],
    )


BASE = datetime(2020, 1, 1, tzinfo=UTC)


def _days(*offsets: int) -> list[DmarcReport]:
    """Reports that many days after 2020-01-01, which is long past."""
    return [_report(BASE + timedelta(days=d)) for d in offsets]


def test_reports_from_years_ago_still_produce_a_window() -> None:
    """The old behaviour refused every one of these and exited."""
    inside, baseline = split_at_window(_days(0, 1, 2), days=21)
    assert len(inside) == 3
    assert baseline == []


def test_the_split_is_measured_from_the_newest_report() -> None:
    """The newest report anchors it, so the two oldest fall outside 21 days."""
    inside, baseline = split_at_window(_days(0, 1, 29, 39), days=21)
    assert [r.report_id for r in inside] == ["2020-01-30", "2020-02-09"]
    assert [r.report_id for r in baseline] == ["2020-01-01", "2020-01-02"]


def test_the_newest_report_is_always_inside_its_own_window() -> None:
    for days in (1, 7, 21, 365):
        inside, _ = split_at_window(_days(0, 99, 199), days=days)
        assert inside, f"nothing inside for days={days}"
        assert inside[-1].report_id == "2020-07-18"


def test_the_answer_does_not_depend_on_when_it_is_run() -> None:
    """Same batch, same split, whatever the clock says."""
    batch = _days(0, 1, 29, 39)
    first = split_at_window(batch, days=21)
    second = split_at_window(batch, days=21)
    assert [r.report_id for r in first[0]] == [r.report_id for r in second[0]]
    assert [r.report_id for r in first[1]] == [r.report_id for r in second[1]]


def test_a_report_with_no_date_stays_inside() -> None:
    """It cannot be shown to predate the window, and a wrong baseline is worse
    than a missing one."""
    undated = DmarcReport(
        org_name="yahoo.com",
        report_id="undated",
        date_begin=None,
        date_end=None,
        policy=DmarcPolicyPublished(domain=DOMAIN, p="none", adkim="r", aspf="r"),
        records=[],
    )
    inside, baseline = split_at_window([undated, *_days(0, 59)], days=21)
    assert "undated" in [r.report_id for r in inside]
    assert [r.report_id for r in baseline] == ["2020-01-01"]


def test_an_empty_batch_is_empty_not_an_error() -> None:
    assert split_at_window([], days=21) == ([], [])
