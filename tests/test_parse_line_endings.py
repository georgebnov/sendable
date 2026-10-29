"""The parser hands every consumer the same line endings.

A mail transfer agent sends CRLF between lines, so an HTML part arrives with
`\r\n`. `lxml` used to normalise that to `\n` on its way through
BeautifulSoup, and every word count, paragraph split, and regex that matches
`\n` depended on it without saying so. The stdlib parser does not normalise,
so `parse_eml` does it instead and the behaviour belongs to this repository
rather than to a parser choice.
"""

from __future__ import annotations

from engine.parse import parse_eml

_CRLF_MESSAGE = (
    b"From: Sender <s@example.com>\r\n"
    b"To: Reader <r@example.com>\r\n"
    b"Subject: Line endings\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"\r\n"
    b"<p>first line</p>\r\n<p>second line</p>\r\n"
)


def test_html_carries_no_carriage_returns() -> None:
    email = parse_eml(_CRLF_MESSAGE)
    assert email.html is not None
    assert "\r" not in email.html


def test_the_text_itself_is_unchanged() -> None:
    """Only the line ending changes. No content is added or dropped."""
    email = parse_eml(_CRLF_MESSAGE)
    assert email.html is not None
    assert email.html.replace("\n", "") == ("<p>first line</p><p>second line</p>")
