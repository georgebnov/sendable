"""Regressions for the fifth review round, on the finding text itself.

The round that rewrote every copy finding left four defects of the same class
it set out to remove, and the gate it added could not see them:

- `['mailer-example.com']` still reaches a sender from three message sites,
  because each one interpolates a plain name that holds a list, and the static
  gate only reads the expression it is given.
- The hidden-text finding counts pattern matches and calls them places, so one
  hidden `<div>` reads as two.
- The body-length pass line says a 500 word body is "inside the 450".
- The trigger-phrase finding tells a sender to say `!!!` in plain words.
"""

from __future__ import annotations

import asyncio

from engine.critic import _check_body_length, _check_links, _check_spam_triggers
from engine.domain.auth import alignment
from engine.domain.integrity import headers as headers_check
from engine.domain.integrity import hidden_css
from engine.parse import ParsedEmail, parse_eml

_CONTAINER_CHARS = "[]{}'"


def _email(raw: bytes) -> ParsedEmail:
    return parse_eml(raw)


# ─── a Python list in a sentence ───────────────────────────────────────────

_UNALIGNED = (
    b"From: Deals <a@shady-example.net>\r\n"
    b"To: r@gmail.com\r\n"
    b"Reply-To: x@other-example.org\r\n"
    b"Subject: hello\r\n"
    b"DKIM-Signature: v=1; a=rsa-sha256; d=mailer-example.com; s=s1; h=from:to; b=aaa\r\n"
    b"Content-Type: text/plain\r\n\r\nhello\r\n"
)


def test_dkim_alignment_names_the_signing_domain_in_prose() -> None:
    findings = asyncio.run(alignment.run(_email(_UNALIGNED)))
    message = next(
        f.message for f in findings if f.check.endswith("dmarc_alignment_dkim") and not f.passed
    )
    assert "mailer-example.com" in message
    for ch in _CONTAINER_CHARS:
        assert ch not in message, message


def test_reply_to_alignment_names_the_domain_in_prose() -> None:
    findings = asyncio.run(alignment.run(_email(_UNALIGNED)))
    message = next(
        f.message for f in findings if f.check.endswith("reply_to_alignment") and not f.passed
    )
    assert "other-example.org" in message
    for ch in _CONTAINER_CHARS:
        assert ch not in message, message


def test_duplicate_headers_names_the_header_in_prose() -> None:
    raw = (
        b"From: Jane <jane@example.com>\r\n"
        b"To: r@gmail.com\r\n"
        b"Subject: hello\r\n"
        b"Subject: hello again\r\n"
        b"Content-Type: text/plain\r\n\r\nhello\r\n"
    )
    findings = asyncio.run(headers_check.run(_email(raw)))
    message = next(
        f.message for f in findings if f.check.endswith("duplicate_headers") and not f.passed
    )
    assert "subject" in message
    for ch in _CONTAINER_CHARS:
        assert ch not in message, message


# ─── one hidden element is one place ──────────────────────────────────────


def test_hidden_text_counts_places_not_pattern_matches() -> None:
    """Two hidden-style properties on one `<div>` read as "2 places"."""
    raw = (
        b"From: Jane <jane@example.com>\r\n"
        b"To: r@gmail.com\r\n"
        b"Subject: hello\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b'<html><body><div style="display:none;font-size:0px">'
        b"Buy our wonderful product today for cheap</div>"
        b"<p>hello there friend</p></body></html>\r\n"
    )
    finding = asyncio.run(hidden_css.run(_email(raw)))[0]
    assert len(finding.details["hits"]) == 2, "the fixture must match two patterns on one element"
    assert "in 1 place " in finding.message, finding.message


# ─── the body-length pass line ────────────────────────────────────────────


def test_a_body_over_the_target_does_not_claim_to_be_inside_it() -> None:
    """The check fires at half again over the target, so 451 to 675 words pass
    while the sentence said they were inside 450."""
    finding = _check_body_length("word " * 500, "long")[0]
    assert finding.passed
    assert "inside the 450" not in finding.message, finding.message
    assert "500 words" in finding.message


# ─── punctuation is not wording ───────────────────────────────────────────


def test_a_punctuation_trigger_says_to_remove_it() -> None:
    findings, _ = _check_spam_triggers("BUY!!!", "", "", {"formatting": ["!!!"]})
    message = findings[0].message
    assert "say the same thing in plain words" not in message, message
    assert "remove it" in message


def test_the_newsletter_word_trigger_names_the_open_rate() -> None:
    findings, _ = _check_spam_triggers(
        "our newsletter", "", "", {"newsletter-word": ["newsletter"]}
    )
    message = findings[0].message
    assert "say the same thing in plain words" not in message, message
    assert "open rate" in message


# ─── one link is one link ─────────────────────────────────────────────────


def test_a_single_link_is_singular() -> None:
    finding = next(f for f in _check_links("word " * 50 + " https://example.com/a") if f.passed)
    assert "1 link in" in finding.message, finding.message
    assert "1 links" not in finding.message


def test_no_links_is_plural() -> None:
    finding = next(f for f in _check_links("word " * 50) if f.passed)
    assert "0 links in" in finding.message, finding.message


def test_a_google_docs_link_is_not_called_drive() -> None:
    findings = _check_links("see https://docs.google.com/document/d/x")
    message = next(f.message for f in findings if f.check.endswith("drive_link") and not f.passed)
    assert "Google Docs" in message, message
    assert "Google Drive at" not in message
