"""Characters that impersonate Latin letters, and the ones that do not.

A homoglyph attack writes a familiar word with letters from another alphabet
that happen to look the same, so `pаypal` with a Cyrillic а reads as `paypal`
to a person and as a different string to a machine. In a link it is the classic
phishing pattern.

The hard part is not finding non-Latin letters. It is not shouting at an email
that is simply written in another language. A Russian newsletter is full of
Cyrillic and impersonates nothing, so the rule is about the contrast: non-Latin
letters that look Latin, inside text that is otherwise Latin.
"""

from __future__ import annotations

import asyncio
from email.message import EmailMessage

import pytest

from engine.domain.integrity import homoglyph
from engine.parse import parse_eml
from engine.severity import Severity

# Built from code points, never literals. `ruff format` rewrites a \\u escape
# into the character it names, and `ruff check` then flags that character as
# ambiguous, which is the rule this very module exists to enforce. chr() says
# exactly which character is meant and no formatter can rewrite it.
CYRILLIC_A = chr(0x0430)
CYRILLIC_O = chr(0x043E)
GREEK_OMICRON = chr(0x03BF)
# paypa, with every letter Cyrillic and not one Latin character in it.
PURE_CYRILLIC_PAYPAL = "".join(chr(c) for c in (0x0440, 0x0430, 0x0443, 0x0440, 0x0430))

RUSSIAN_SUBJECT = "".join(
    chr(c) for c in (0x0412, 0x0430, 0x0448, 0x20, 0x0441, 0x0447, 0x0451, 0x0442)
)
RUSSIAN_BODY = "".join(
    chr(c)
    for c in (
        0x0417,
        0x0434,
        0x0440,
        0x0430,
        0x0432,
        0x0441,
        0x0442,
        0x0432,
        0x0443,
        0x0439,
        0x0442,
        0x0435,
        0x2C,
        0x20,
        0x0432,
        0x043E,
        0x0442,
        0x20,
        0x0432,
        0x0430,
        0x0448,
        0x20,
        0x0441,
        0x0447,
        0x0451,
        0x0442,
    )
)
GREEK_SUBJECT = "".join(chr(c) for c in (0x03A4, 0x03BF, 0x20, 0x03C4, 0x03B9, 0x03BC, 0x03AE))
GREEK_BODY = "".join(
    chr(c)
    for c in (
        0x039A,
        0x03B1,
        0x03BB,
        0x03B7,
        0x03BC,
        0x03AD,
        0x03C1,
        0x03B1,
        0x2C,
        0x20,
        0x03B1,
        0x03C5,
        0x03C4,
        0x03CC,
        0x20,
        0x03B5,
        0x03AF,
        0x03BD,
        0x03B1,
        0x03B9,
        0x20,
        0x03C4,
        0x03BF,
    )
)
ACCENTED = "".join(chr(c) for c in (0x43, 0x61, 0x66, 0x00E9, 0x20, 0x6E, 0x61, 0x00EF, 0x76, 0x65))
EMOJI = chr(0x1F4E6)
EURO = chr(0x20AC)


def _email(subject: str = "Hello", html: str = "<p>Hello</p>"):
    msg = EmailMessage()
    msg["From"] = "Sender <s@example.com>"
    msg["To"] = "r@example.com"
    msg["Subject"] = subject
    msg.set_content("plain")
    msg.add_alternative(html, subtype="html")
    return parse_eml(msg.as_bytes())


def _run(email) -> list:
    return asyncio.run(homoglyph.run(email))


# ── it catches the attack ────────────────────────────────────────────────


def test_one_cyrillic_letter_hidden_in_an_english_subject() -> None:
    findings = _run(_email(subject=f"Sign in to p{CYRILLIC_A}ypal"))
    assert findings and findings[0].passed is False
    assert findings[0].details["hits"][0]["alias"] == "CYRILLIC"


def test_a_greek_letter_hidden_in_english_body_text() -> None:
    findings = _run(_email(html=f"<p>Your amaz{GREEK_OMICRON}n order shipped</p>"))
    assert findings and findings[0].details["hits"][0]["alias"] == "GREEK"


def test_a_word_written_entirely_in_a_lookalike_alphabet() -> None:
    """Mixing scripts is the easy case. A word with no Latin in it at all,
    inside an English message, is the one a simpler rule would miss."""
    findings = _run(_email(html=f"<p>Please sign in at {PURE_CYRILLIC_PAYPAL}.com today</p>"))
    assert findings


def test_a_lookalike_in_a_link_is_critical() -> None:
    """In a hostname it is phishing, not a typo."""
    html = f'<p>Click <a href="http://g{CYRILLIC_O}ogle.com/login">here</a></p>'
    findings = _run(_email(html=html))
    assert findings and findings[0].severity is Severity.CRITICAL


def test_a_lookalike_in_ordinary_text_is_not_critical() -> None:
    findings = _run(_email(subject=f"Your amaz{CYRILLIC_O}n order"))
    assert findings and findings[0].severity is Severity.HIGH


# ── it stays quiet when nothing is impersonating anything ────────────────


@pytest.mark.parametrize(
    ("name", "subject", "html"),
    [
        ("plain english", "Your invoice", "<p>Click here to view it</p>"),
        ("a russian newsletter", RUSSIAN_SUBJECT, f"<p>{RUSSIAN_BODY}</p>"),
        ("a greek newsletter", GREEK_SUBJECT, f"<p>{GREEK_BODY}</p>"),
        ("accented french", ACCENTED, "<p>Resume attached</p>"),
        ("emoji", f"Your order {EMOJI}", f"<p>It shipped {EMOJI}</p>"),
        ("currency", f"Invoice {EURO}49", f"<p>Total: {EURO}10</p>"),
    ],
)
def test_it_reports_nothing(name: str, subject: str, html: str) -> None:
    """A clean message still returns the passing INFO row, with no hits in it."""
    findings = _run(_email(subject=subject, html=html))
    assert all(f.passed for f in findings), [f.details for f in findings if not f.passed]
