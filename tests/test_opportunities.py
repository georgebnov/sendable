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


# ── a lookup that failed is not a fact about the domain ──────────────────


def _bimi_after_dns_failure(error: str) -> Finding:
    """What modern_records emits when the DMARC lookup itself did not answer.
    `eligible` is False and `dmarc_policy` is None, but only because nothing
    came back, not because the domain publishes p=none."""
    return Finding(
        check="bimi.published",
        severity=Severity.INFO,
        passed=False,
        message="",
        details={"dns_error": error, "eligible": False, "dmarc_policy": None},
    )


@pytest.mark.parametrize("error", ["timeout", "no_nameservers", "error:OSError"])
def test_a_failed_lookup_says_nothing_rather_than_guessing(error: str) -> None:
    """It used to announce "Your DMARC policy is p=none" to a domain it could
    not reach, which may well publish p=reject. Silence is the honest answer
    and the function's own docstring already promised it."""
    assert (
        _by_id(opportunities_from([_bimi_after_dns_failure(error)]), "inbox_presence.bimi") is None
    )


def test_a_real_p_none_still_reports_blocked() -> None:
    """The fix must not swallow the case it exists for: the lookup worked and
    the policy really is none."""
    bimi = _by_id(opportunities_from([_bimi(False, "none")]), "inbox_presence.bimi")
    assert bimi is not None and bimi.state == "blocked"


# ── the sender who already has a Google Account ──────────────────────────


@pytest.mark.parametrize("address", ["Someone <me@gmail.com>", "me@googlemail.com"])
def test_a_gmail_sender_is_not_told_to_make_an_account(address: str) -> None:
    """They have one. Telling them to sign up with an existing address and
    confirm a code describes a path they cannot take."""
    picture = _by_id(opportunities_from([], from_addr=address), "inbox_presence.profile_picture")
    assert picture is not None
    joined = " ".join(picture.steps).lower()
    assert "sign-up" not in joined and "sign up" not in joined
    assert "confirm the code" not in joined
    assert "photo" in joined, "they still need to set one"


def test_a_sender_on_their_own_domain_gets_the_full_steps() -> None:
    picture = _by_id(
        opportunities_from([], from_addr="hello@example.com"),
        "inbox_presence.profile_picture",
    )
    assert picture is not None
    assert "existing" in " ".join(picture.steps).lower()


def test_no_address_at_all_gets_the_full_steps() -> None:
    """Offline, or a message with no From, must not lose the opportunity."""
    picture = _by_id(opportunities_from([]), "inbox_presence.profile_picture")
    assert picture is not None and picture.steps
