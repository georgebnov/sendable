"""Every message `engine/critic.py` can produce, read once by a test.

The copy checks are the ones a sender acts on, and most of these paths ran in no
test at all. `just coverage` showed the rewritten `issues.append(` and
`findings.append(` lines uncovered, which means the sentence a user would read
had never been executed. A message that is never rendered is a message nobody
has checked.

`tests/test_message_quality.py` gates the shapes that must never appear.
This renders each message and reads it. The two together are what makes the
text checked rather than assumed.

The `_check_*` functions are private, and `engine/copywriting/heuristics.py`
imports them exactly as these tests do. That is the seam the only caller uses.
"""

from __future__ import annotations

import pytest

from engine.critic import (
    _check_body_emoji,
    _check_body_length,
    _check_body_newsletter_word,
    _check_body_shouting,
    _check_compound_signal,
    _check_links,
    _check_spam_triggers,
    _check_subjects,
)
from engine.severity import Severity

TRIGGERS = {
    "urgency": ["act now"],
    "commerce-cta": ["click here"],
    "financial-promise": ["guaranteed"],
    "fomo": ["last chance"],
    "generic-greeting": ["dear friend"],
    "formatting": ["!!!"],
}


def _failing(findings: list) -> list[str]:
    return [f.message for f in findings if not f.passed]


def _only(findings: list) -> str:
    """The one failing message, so a test that triggers two paths is obvious."""
    messages = _failing(findings)
    assert len(messages) == 1, f"expected one finding, got {messages}"
    return messages[0]


# ── the subject line ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("subject", "expected", "severity"),
    [
        (
            "A subject line written far past the fifty character limit it has",
            "is 64 characters long. Keep it to 50 or fewer",
            Severity.MEDIUM,
        ),
        (
            "one two three four five six seven eight nine",
            "is 9 words. Keep it to 8 or fewer",
            Severity.LOW,
        ),
        ("Your Monthly Water Report", "is in Title Case. Use sentence case", Severity.MEDIUM),
        ("URGENT LIMITED OFFER", "uses capitals for whole words", Severity.HIGH),
        ("hi there!! open this!", "has more than one exclamation mark", Severity.MEDIUM),
        ("what? really? how so", "has more than one question mark", Severity.LOW),
        ("Re: your account", "starts with Re: or Fwd:", Severity.HIGH),
        ("our newsletter for you", "the word newsletter", Severity.LOW),
        ("hello \U0001f600 there \U0001f601", "has 2 emoji. Keep one at most", Severity.MEDIUM),
        ("$50 off today", "opens with a price", Severity.MEDIUM),
    ],
)
def test_each_subject_problem_names_the_field_and_the_fix(
    subject: str, expected: str, severity: Severity
) -> None:
    findings = _check_subjects([subject])
    matched = [f for f in findings if not f.passed and expected in f.message]
    assert matched, f"no message contained {expected!r}. Got: {_failing(findings)}"
    assert matched[0].message.startswith("The subject line"), matched[0].message
    assert matched[0].severity == severity


def test_a_single_subject_is_not_numbered() -> None:
    """`subject variant 0:` numbered a subject line written once."""
    message = _check_subjects(["URGENT LIMITED OFFER"])[0].message
    assert message.startswith("The subject line")
    assert "variant" not in message
    assert "0" not in message


def test_several_subjects_say_which_one() -> None:
    """A draft carrying alternatives does need the number, in human counting."""
    findings = _check_subjects(["fine subject here", "URGENT LIMITED OFFER", "also fine"])
    failing = _failing(findings)
    assert len(failing) == 1
    assert failing[0].startswith("Subject line 2 of 3 uses capitals")


def test_a_clean_subject_says_there_is_nothing_to_fix() -> None:
    findings = _check_subjects(["your water bill fell this month"])
    assert len(findings) == 1
    assert findings[0].passed
    assert findings[0].message == "Nothing to fix in the subject line."


def test_several_clean_subjects_count_themselves() -> None:
    findings = _check_subjects(["your water bill fell", "water use fell again"])
    assert findings[0].message == "Nothing to fix in any of the 2 subject lines."


# ── filter-triggering wording ──────────────────────────────────────────────


@pytest.mark.parametrize(
    ("field", "named"),
    [("subject", "subject line"), ("preview", "preview text field"), ("body", "body")],
)
def test_a_trigger_phrase_names_the_part_of_the_composer(field: str, named: str) -> None:
    fields = {"subject": "", "preview": "", "body": ""}
    fields[field] = "please act now"
    findings, fired = _check_spam_triggers(
        fields["subject"], fields["preview"], fields["body"], {"urgency": ["act now"]}
    )
    assert _only(findings) == (
        f'The {named} contains "act now". Bulk filters score that wording, '
        f"so say the same thing in plain words."
    )
    assert fired == {"urgency"}


def test_no_trigger_phrase_names_all_three_places() -> None:
    findings, fired = _check_spam_triggers("hello", "a short note", "plain words", TRIGGERS)
    assert not fired
    assert findings[0].message == (
        "No filter-triggering wording in the subject line, the preview text or the body."
    )


# ── stacked promotional language ───────────────────────────────────────────


def test_no_stacked_language() -> None:
    assert _check_compound_signal(set())[0].message == "The copy stacks no promotional language."


def test_below_the_stack_names_what_it_found_in_words() -> None:
    message = _check_compound_signal({"urgency", "financial-promise"})[0].message
    assert message == (
        "The copy uses a money promise and urgency, below the 3 kinds that count as a stack."
    )


@pytest.mark.parametrize(
    ("categories", "severity"),
    [
        ({"urgency", "fomo", "commerce-cta"}, Severity.MEDIUM),
        ({"urgency", "fomo", "commerce-cta", "financial-promise"}, Severity.HIGH),
        (
            {"urgency", "fomo", "commerce-cta", "financial-promise", "generic-greeting"},
            Severity.CRITICAL,
        ),
    ],
)
def test_a_stack_names_the_kinds_in_words(categories: set[str], severity: Severity) -> None:
    finding = _check_compound_signal(categories)[0]
    assert finding.severity == severity
    assert f"stacks {len(categories)} kinds of promotional language at once" in finding.message
    assert "keep one and cut the rest" in finding.message
    # No internal label survives. Every slug that carries a dash is renamed, and
    # rule 12 keeps a dash out of text a user reads either way.
    assert "-" not in finding.message, finding.message


def test_a_category_with_no_name_loses_its_dashes() -> None:
    """Rule 12 keeps a dash out of text a user reads, and a new slug in
    spam_triggers.md would otherwise carry one straight through."""
    message = _check_compound_signal({"urgency", "fomo", "some-new-label"})[0].message
    assert "some new label" in message
    assert "some-new-label" not in message


# ── body length ────────────────────────────────────────────────────────────


def test_a_long_body_says_the_target_for_that_length() -> None:
    # The check fires at half again over the target, so 450 needs 676 words.
    finding = _check_body_length("word " * 700, "long")[0]
    assert finding.message == (
        "The body is 700 words. A long email should run to about 450, so cut it back."
    )


def test_a_short_email_past_300_words_says_so() -> None:
    messages = _failing(_check_body_length("word " * 400, "short"))
    assert any(
        m
        == (
            "The body is 400 words. A short email that runs past 300 words is no "
            "longer short, so split it or cut it."
        )
        for m in messages
    ), messages


def test_a_body_inside_the_target_says_the_target() -> None:
    finding = _check_body_length("word " * 150, "short")[0]
    assert finding.passed
    assert finding.message == "The body is 150 words, inside the 200 a short email should run."


# ── links ──────────────────────────────────────────────────────────────────


def test_too_many_links_says_how_many_to_remove() -> None:
    body = "word " * 100 + " ".join(f"https://example.com/{n}" for n in range(7))
    message = next(m for m in _failing(_check_links(body)) if "links in" in m)
    assert "The body has 7 links in 107 words." in message
    assert "this length carries 2, so remove 5." in message
    assert "max(" not in message and "/125" not in message


def test_a_link_count_inside_the_budget_states_it_plainly() -> None:
    finding = next(f for f in _check_links("word " * 50 + " https://example.com/a") if f.passed)
    assert finding.message == "The body has 1 links in 51 words, inside the 2 this length carries."


def test_a_drive_link_says_where_to_put_the_file_instead() -> None:
    message = next(
        m for m in _failing(_check_links("see https://drive.google.com/file/d/x")) if "Drive" in m
    )
    assert message == (
        "The body links to Google Drive at https://drive.google.com/file/d/x. Filters "
        "treat a shared-document link as high risk, so host the file on your own "
        "domain or attach it."
    )


def test_no_drive_link_says_so() -> None:
    finding = next(f for f in _check_links("plain words only") if f.check.endswith("drive_link"))
    assert finding.message == "No Google Drive or Google Docs links in the body."


# ── shouting ───────────────────────────────────────────────────────────────


def test_shouting_quotes_the_line_it_found() -> None:
    message = next(
        m
        for m in _failing(_check_body_shouting("hello there\nLIMITED URGENT OFFER TODAY"))
        if "capitals" in m
    )
    assert message == (
        'The body uses capitals for whole words, starting with "LIMITED URGENT OFFER '
        'TODAY". Write them in normal case.'
    )


def test_shouting_inside_a_longer_sentence_is_found_too() -> None:
    """The second detection path: 3 capitalised words in a row inside a line
    that is mostly lowercase, so the share-of-the-line rule does not fire."""
    line = "we think you should really consider this and LIMITED URGENT OFFER today for you"
    message = next(m for m in _failing(_check_body_shouting(line)) if "capitals" in m)
    assert message.startswith('The body uses capitals for whole words, starting with "we think')
    assert message.endswith("Write them in normal case.")


def test_stacked_exclamation_marks_quote_the_line() -> None:
    message = next(m for m in _failing(_check_body_shouting("buy it now!!")) if "stacks" in m)
    assert message == (
        'The body stacks exclamation marks, starting with "buy it now!!". Keep one at most.'
    )


def test_many_exclamation_marks_give_the_count_and_the_limit() -> None:
    message = next(
        m for m in _failing(_check_body_shouting("one! two! three! four!")) if "marks." in m
    )
    assert message == "The body has 4 exclamation marks. Keep it to 3 or fewer."


def test_a_calm_body_says_so() -> None:
    finding = _check_body_shouting("a calm line of plain words")[0]
    assert finding.passed
    assert finding.message == (
        "The body does not use capitals for whole words or stack exclamation marks."
    )


# ── the newsletter word and emoji ──────────────────────────────────────────


def test_the_newsletter_word_keeps_its_figure_without_the_vendor() -> None:
    """The 18.7 percent claim is the repo's, so it stays. "Zippia" was a source
    citation in the middle of advice, which is not what a sender needs."""
    message = _check_body_newsletter_word("our newsletter is here")[0].message
    assert message == (
        "The body contains the word newsletter, which measures about 19 percent "
        "worse on open rate. Say what is inside the email instead."
    )
    assert "Zippia" not in message


def test_no_newsletter_word_says_so() -> None:
    assert _check_body_newsletter_word("a plain update")[0].message == (
        "The body does not use the word newsletter."
    )


def test_too_many_emoji_count_both_fields() -> None:
    message = _check_body_emoji("hi \U0001f600", "there \U0001f601 and \U0001f602")[0].message
    assert message == ("The subject line and body together have 3 emoji. Keep one at most.")


def test_one_emoji_passes_and_says_the_count() -> None:
    finding = _check_body_emoji("hi \U0001f600", "plain body")[0]
    assert finding.passed
    assert finding.message == "The subject line and body together have 1 emoji."
