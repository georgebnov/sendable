"""Turning a test send into the production email it stands for.

A marketer audits a test send, which is the same content a recipient would get
plus a few markers: a TEST prefix on the subject, the ESP's test headers, and raw
merge tags that have not been filled in yet. Scoring those markers would grade the
test rather than the campaign, so cleanup removes them first.

Two properties matter beyond "it strips things". It must be idempotent, because an
audit may run twice. And it must not touch an email that carries no markers, since
most audited mail is a real send.
"""

from __future__ import annotations

import random

import pytest

from engine.cleanup import cleanup
from engine.parse import ParsedEmail, parse_eml


@pytest.fixture(autouse=True)
def _fixed_random() -> None:
    # Merge tags are replaced with a fake value chosen at random, so the same
    # input otherwise produces different output on every run.
    random.seed(1234)


def _email(
    subject: str = "Office hours Saturday",
    *,
    html: str = "<html><body><p>Hello.</p></body></html>",
    plain: str = "Hello.",
    headers: dict[str, list[str]] | None = None,
    from_addr: str = "Jane Okafor <jane@example.com>",
    to: list[str] | None = None,
) -> ParsedEmail:
    base: dict[str, list[str]] = {
        "from": [from_addr],
        "to": to or ["reader@gmail.com"],
        "subject": [subject],
    }
    base.update(headers or {})
    lines = "".join(f"{k.title()}: {v[0]}\r\n" for k, v in base.items())
    raw = (lines + "Content-Type: text/html\r\n\r\n" + html).encode()
    parsed = parse_eml(raw)
    return ParsedEmail(
        raw=parsed.raw,
        headers={k: list(v) for k, v in base.items()},
        html=html,
        plain_text=plain,
        from_addr=from_addr,
        to_addrs=to or ["reader@gmail.com"],
        subject=subject,
        authentication_results=[],
        received_at=None,
    )


# ── the subject prefix ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "subject",
    [
        "[TEST] Office hours Saturday",
        "TEST: Office hours Saturday",
        "[Preview] Office hours Saturday",
        "[STAGING] - Office hours Saturday",
        "[test][preview] Office hours Saturday",
    ],
)
def test_a_test_prefix_is_stripped(subject: str) -> None:
    cleaned, report = cleanup(_email(subject))
    assert cleaned.subject == "Office hours Saturday"
    assert report.subject_prefix_stripped is not None


def test_a_subject_that_merely_mentions_a_test_is_left_alone() -> None:
    # The prefix rule anchors at the start. "Test drive our new tool" is copy.
    cleaned, report = cleanup(_email("Test drive our new tool this Saturday"))
    assert cleaned.subject == "Test drive our new tool this Saturday"
    assert report.subject_prefix_stripped is None


# ── the ESP's own test headers ─────────────────────────────────────────────


def test_an_esp_test_header_is_removed() -> None:
    cleaned, report = cleanup(_email(headers={"x-mailchimp-test": ["true"]}))
    assert "x-mailchimp-test" not in cleaned.headers
    assert "x-mailchimp-test" in report.headers_stripped


def test_an_ordinary_header_is_kept() -> None:
    cleaned, _ = cleanup(_email(headers={"list-unsubscribe": ["<https://example.com/u>"]}))
    assert "list-unsubscribe" in cleaned.headers


# ── merge tags ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "tag",
    ["{{FIRST_NAME}}", "*|FNAME|*", "%%first_name%%", "[FIRST NAME]", "{{ first_name }}"],
)
def test_a_merge_tag_is_replaced_with_a_plausible_value(tag: str) -> None:
    # An unfilled tag in the body is a test artifact. Left in place, the copy
    # checks grade a greeting that reads "Hi {{FIRST_NAME}}", which is not what
    # the recipient would see.
    cleaned, report = cleanup(_email(html=f"<html><body><p>Hi {tag},</p></body></html>"))
    assert tag not in (cleaned.html or "")
    assert report.placeholders_substituted


def test_an_unsubscribe_tag_becomes_a_url_not_a_name() -> None:
    # link_quality and url_reputation parse this as an href. Collapsing it to a
    # first name would make a working unsubscribe link look broken.
    cleaned, _ = cleanup(
        _email(html='<html><body><a href="{{UNSUBSCRIBE_URL}}">Unsubscribe</a></body></html>')
    )
    assert "https://" in (cleaned.html or "")


def test_a_link_tag_becomes_a_url() -> None:
    cleaned, _ = cleanup(_email(html='<html><body><a href="*|LINK_URL|*">Read</a></body></html>'))
    assert "https://" in (cleaned.html or "")


def test_an_outlook_conditional_comment_is_not_substituted() -> None:
    # [if mso] and [endif] are bracket syntax every HTML email carries. Replacing
    # them would corrupt the markup the template-quality check then reads.
    html = "<html><body><!--[if mso]><table><![endif]--><p>Hi.</p></body></html>"
    cleaned, _ = cleanup(_email(html=html))
    assert "[if mso]" in (cleaned.html or "")
    assert "[endif]" in (cleaned.html or "")


def test_a_merge_tag_in_the_subject_is_replaced() -> None:
    cleaned, _ = cleanup(_email("Hi {{FIRST_NAME}}, office hours Saturday"))
    assert "{{FIRST_NAME}}" not in (cleaned.subject or "")


# ── display names, but never the address ───────────────────────────────────


def test_a_merge_tag_in_the_from_display_name_is_replaced() -> None:
    cleaned, _ = cleanup(_email(from_addr="{{AGENT_NAME}} <jane@example.com>"))
    assert "{{AGENT_NAME}}" not in (cleaned.from_addr or "")


def test_the_sending_address_is_never_changed() -> None:
    # Every authentication and alignment check reads this domain. Substituting it
    # would make a correctly aligned sender look unaligned.
    cleaned, _ = cleanup(_email(from_addr="{{AGENT_NAME}} <jane@example.com>"))
    assert "jane@example.com" in (cleaned.from_addr or "")


# ── the two properties that matter most ────────────────────────────────────


def test_cleanup_is_idempotent() -> None:
    # An audit may run twice over the same message. A second pass must find
    # nothing left to do, or the stored report changes for no reason.
    first, _ = cleanup(_email("[TEST] Hi {{FIRST_NAME}}", headers={"x-test": ["1"]}))
    second, report = cleanup(first)
    assert second.subject == first.subject
    assert second.html == first.html
    assert report.subject_prefix_stripped is None
    assert report.headers_stripped == []


def test_a_production_email_passes_through_unchanged() -> None:
    # Most audited mail is a real send. Cleanup runs on it too and must be a no-op.
    original = _email()
    cleaned, report = cleanup(original)
    assert cleaned.subject == original.subject
    assert cleaned.html == original.html
    assert cleaned.from_addr == original.from_addr
    assert report.subject_prefix_stripped is None
    assert report.headers_stripped == []
    assert report.placeholders_substituted == []


def test_the_original_email_is_not_mutated() -> None:
    original = _email("[TEST] Office hours", headers={"x-test": ["1"]})
    before = original.subject
    cleanup(original)
    assert original.subject == before
    assert "x-test" in original.headers


# ── nothing to clean ───────────────────────────────────────────────────────


def test_an_empty_email_does_not_raise() -> None:
    cleaned, report = cleanup(parse_eml(b""))
    assert cleaned is not None
    assert report.subject_prefix_stripped is None
