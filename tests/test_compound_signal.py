"""The compound-signal score, and the category set it counts.

One promotional phrase is noise. Several categories of promotional phrase in one
email is the pattern providers quarantine, so `compound_signal` counts DISTINCT
categories rather than phrases. `formatting` and `newsletter-word` are excluded,
because either fires on ordinary mail.

The tiers are fixed: 3 categories is MEDIUM, 4 is HIGH, 5 or more is CRITICAL.
The number of categories available is not fixed, because the category list lives
in `engine/context/spam_triggers.md` for a user to edit. These tests read the
real file, so deleting a category tells you here that a tier boundary moved.
"""

from __future__ import annotations

from engine.critic import _check_compound_signal, _check_spam_triggers, _load_trigger_map

# Not counted toward the promotional score. See the module docstring.
_EXCLUDED = {"formatting", "newsletter-word", "uncategorised"}


def _promotional_categories() -> set[str]:
    return set(_load_trigger_map()) - _EXCLUDED


def _score(subject: str = "", preview: str = "", body: str = "") -> tuple[str, list[str]]:
    _, fired = _check_spam_triggers(subject, preview, body, _load_trigger_map())
    findings = _check_compound_signal(fired)
    assert len(findings) == 1
    return findings[0].severity, findings[0].details["categories"]


def test_the_shipped_list_holds_five_promotional_categories() -> None:
    # The CRITICAL tier starts at 5. With exactly 5 categories available,
    # CRITICAL means every one of them fired. Deleting one makes CRITICAL
    # unreachable, and adding one makes it reachable without all of them.
    assert _promotional_categories() == {
        "urgency",
        "fomo",
        "commerce-cta",
        "financial-promise",
        "generic-greeting",
    }


def test_one_category_is_below_the_threshold() -> None:
    severity, categories = _score(subject="Act now")
    assert severity == "INFO"
    assert categories == ["urgency"]


def test_two_categories_are_still_below_the_threshold() -> None:
    severity, _ = _score(subject="Act now", body="Buy now.")
    assert severity == "INFO"


def test_three_categories_are_medium() -> None:
    severity, categories = _score(subject="Act now", body="Buy now and save up to half.")
    assert severity == "MEDIUM"
    assert len(categories) == 3


def test_four_categories_are_high() -> None:
    severity, categories = _score(
        subject="Act now, exclusive offer", body="Buy now and save up to half."
    )
    assert severity == "HIGH"
    assert len(categories) == 4


def test_all_five_categories_are_critical() -> None:
    severity, categories = _score(
        subject="Act now, exclusive offer",
        body="Dear valued customer, buy now and save up to half.",
    )
    assert severity == "CRITICAL"
    assert len(categories) == 5


def test_formatting_alone_does_not_count() -> None:
    # `!!!` fires the formatting category. On its own it must not move the score,
    # because an excited subject line is not a promotional pattern.
    severity, categories = _score(subject="Thanks!!!")
    assert severity == "INFO"
    assert categories == []


def test_the_newsletter_word_alone_does_not_count() -> None:
    severity, categories = _score(subject="The weekly newsletter")
    assert severity == "INFO"
    assert categories == []


def test_an_email_with_no_trigger_phrase_passes() -> None:
    severity, categories = _score(
        subject="Office hours Saturday", body="Reply to this email to claim a seat."
    )
    assert severity == "INFO"
    assert categories == []
