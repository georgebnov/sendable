"""The advice answers from the reports in front of it, not from a streak.

Sendable collects nothing and remembers nothing. The reports a user passes are
all it will ever see, so advice that counts toward a target it cannot maintain
is advice nobody can act on. The old engine held the user at
"Keep collecting reports. We'll prompt you once there's enough clean volume",
and there is no we, nothing collects, and nothing prompts.

So the engine now says what these reports show and what the next rung is, and
it carries the real caution, that a sender who mails once a month will not
appear in a week of reports, as a thing for the reader to weigh rather than as
a counter the tool pretends to keep.
"""

from __future__ import annotations

import pytest

from engine.dmarc.policy_engine import DmarcRecord, Sender, SpfRecord, Window, evaluate

RUA = "mailto:dmarc@example.com"


def _clean_sender(volume: int = 350) -> Sender:
    return Sender(
        name="Google Workspace",
        volume=volume,
        dkim_aligned=True,
        spf_aligned=True,
        spf_authpassed=True,
        has_dkim_signature=True,
        legitimacy="legit",
        disposition="none",
        classification="clean",
    )


def _window(days: int = 7, volume: int = 350) -> Window:
    return Window(senders=[_clean_sender(volume)], days_with_data=days, total_volume=volume)


def _spf() -> SpfRecord:
    return SpfRecord(exists=True, record_count=1, lookups=3, all_qualifier="~")


@pytest.mark.parametrize(("days", "volume"), [(1, 5), (1, 50), (3, 150), (7, 350), (60, 9000)])
def test_clean_reports_always_get_the_next_step(days: int, volume: int) -> None:
    """However few reports there are, a clean batch gets an answer rather than
    being told to come back later."""
    result = evaluate(
        DmarcRecord(exists=True, p="none", sp="none", pct=100), _spf(), _window(days, volume), RUA
    )
    assert result.primary.code == "ADVANCE"
    assert result.primary.new_record is not None
    assert "quarantine" in result.primary.new_record


def test_the_advice_never_promises_a_reminder() -> None:
    """Nothing runs between invocations, so nothing can prompt anyone."""
    result = evaluate(
        DmarcRecord(exists=True, p="none", sp="none", pct=100), _spf(), _window(1, 5), RUA
    )
    text = " ".join(
        [result.primary.title, result.primary.detail, result.primary.suggested_action]
    ).lower()
    for promise in (
        "we'll prompt",
        "we will prompt",
        "keep collecting",
        "hold steady",
        "clean days",
    ):
        assert promise not in text, f"the advice still promises: {promise!r}"


def test_the_advice_says_what_the_reports_actually_cover() -> None:
    """The reader needs to judge whether the batch is representative, so the
    size of it is stated instead of being scored against a target."""
    result = evaluate(
        DmarcRecord(exists=True, p="none", sp="none", pct=100), _spf(), _window(3, 150), RUA
    )
    text = f"{result.primary.detail} {result.primary.suggested_action}"
    assert "3" in text and "150" in text


def test_a_sender_that_is_failing_still_blocks_the_rung() -> None:
    """Dropping the time gates must not drop the real one."""
    broken = Sender(
        name="Old CRM",
        volume=40,
        dkim_aligned=False,
        spf_aligned=False,
        spf_authpassed=False,
        has_dkim_signature=False,
        legitimacy="legit",
        disposition="none",
        classification="legit_unaligned",
    )
    window = Window(senders=[_clean_sender(), broken], days_with_data=30, total_volume=390)
    result = evaluate(DmarcRecord(exists=True, p="none", sp="none", pct=100), _spf(), window, RUA)
    assert result.primary.code != "ADVANCE"
    assert result.blockers


def test_already_at_the_top_says_so() -> None:
    result = evaluate(
        DmarcRecord(exists=True, p="reject", sp="reject", pct=100), _spf(), _window(), RUA
    )
    assert result.primary.code == "AT_GOAL"
