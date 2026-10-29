"""Things that make a sender recognisable, which are not defects.

The audit scores what is wrong with a message. A missing logo or a missing
profile picture is not wrong: the email is fine and it would simply do better
with a face beside it. Scoring them would mark a correct email down, and adding
a sixth weight to the scorer would re-score every email ever graded, so these
live beside the findings and never touch the score.

Two of them. The profile picture is free and the audit cannot see whether it is
set, so it is always offered. BIMI the audit can read, so its state comes from
what the DNS checks already found.
"""

from __future__ import annotations

import pytest

from engine.opportunities import opportunities_from
from engine.report import Finding
from engine.severity import Severity


def _bimi(eligible: bool, policy: str | None, published: bool = False) -> Finding:
    return Finding(
        check="bimi.published",
        severity=Severity.INFO,
        passed=published,
        message="",
        details={"eligible": eligible, "dmarc_policy": policy},
    )


def _by_id(items, wanted):
    return next((o for o in items if o.id == wanted), None)


# ── the profile picture ──────────────────────────────────────────────────


def test_the_picture_is_always_offered() -> None:
    """Nothing in a message says whether a Google Account has a photo, so the
    audit can never rule it out and always raises it."""
    assert _by_id(opportunities_from([]), "inbox_presence.profile_picture") is not None


def test_the_picture_is_never_blocked_by_anything() -> None:
    """It needs no DNS record and no policy change, which is the whole point of
    leading with it."""
    picture = _by_id(opportunities_from([]), "inbox_presence.profile_picture")
    assert picture is not None
    assert picture.state == "available"
    assert picture.blocked_by is None


def test_the_picture_says_a_google_account_is_not_a_gmail_address() -> None:
    """The step everyone gets wrong. Accepting Gmail creates a mailbox they did
    not want, and the warning on the way reads like an error."""
    picture = _by_id(opportunities_from([]), "inbox_presence.profile_picture")
    assert picture is not None
    joined = " ".join(picture.steps).lower()
    assert "existing" in joined, "the account is made on the address they already use"
    assert "gmail" in joined


# ── BIMI ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("policy", ["none", None])
def test_bimi_is_blocked_below_enforcement(policy: str | None) -> None:
    """A receiver ignores BIMI under p=none, so offering it would waste money."""
    bimi = _by_id(opportunities_from([_bimi(False, policy)]), "inbox_presence.bimi")
    assert bimi is not None
    assert bimi.state == "blocked"
    assert bimi.blocked_by is not None
    assert "quarantine" in bimi.blocked_by


@pytest.mark.parametrize("policy", ["quarantine", "reject"])
def test_bimi_is_ready_at_enforcement(policy: str) -> None:
    bimi = _by_id(opportunities_from([_bimi(True, policy)]), "inbox_presence.bimi")
    assert bimi is not None
    assert bimi.state == "available"
    assert bimi.blocked_by is None


def test_bimi_is_done_when_the_record_is_already_published() -> None:
    bimi = _by_id(
        opportunities_from([_bimi(True, "reject", published=True)]), "inbox_presence.bimi"
    )
    assert bimi is not None
    assert bimi.state == "done"


def test_bimi_says_gmail_charges_for_the_certificate() -> None:
    """Rule 12 in spirit: the cost is the thing a sender needs to know, and
    leaving it out is how someone finds it after publishing the record."""
    bimi = _by_id(opportunities_from([_bimi(True, "reject")]), "inbox_presence.bimi")
    assert bimi is not None
    text = (bimi.detail + " " + " ".join(bimi.steps)).lower()
    assert "certificate" in text, "the paid part is named"
    assert "every year" in text or "expire" in text, "and that it recurs"
    assert "costs nothing" in text, "the picture is named as the alternative"


def test_bimi_is_not_offered_when_the_audit_never_looked() -> None:
    """Offline, or without domain checks, there is no BIMI finding and no way
    to know the policy. Guessing would send the user to buy a certificate that
    their policy makes useless."""
    assert _by_id(opportunities_from([]), "inbox_presence.bimi") is None


# ── the shape ────────────────────────────────────────────────────────────


def test_every_opportunity_carries_steps_a_reader_can_follow() -> None:
    items = opportunities_from([_bimi(True, "reject")])
    assert items
    for item in items:
        assert item.title and item.detail
        assert item.steps, f"{item.id} has nothing to do"
        assert item.state in ("available", "blocked", "done")
