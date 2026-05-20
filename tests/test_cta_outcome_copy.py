"""Primary-CTA outcome-copy check.

Generic action-verb CTA text → MEDIUM.
Outcome-framed CTA text → INFO PASS.
No CTA → INFO PASS.
Button-styled anchor preferred as primary.
"""

from __future__ import annotations

import asyncio
import sys
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.copywriting.cta_outcome_copy import (  # noqa: E402
    _matched_bad_phrase,
    _normalize,
    run,
)
from audit.parse import ParsedEmail  # noqa: E402


def _email(html: str) -> ParsedEmail:
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["Subject"] = "Test"
    msg.set_content("plain", subtype="plain")
    msg.add_alternative(html, subtype="html")
    headers: dict[str, list[str]] = {}
    for k, v in msg.items():
        headers.setdefault(k.lower(), []).append(str(v))
    return ParsedEmail(
        raw=msg,
        headers=headers,
        html=html,
        plain_text="plain",
        from_addr="sender@example.com",
        to_addrs=[],
        subject="Test",
        authentication_results=[],
    )


# ─── Normalization / phrase-match unit ───────────────────────────────


def test_normalize_strips_punct_and_case():
    assert _normalize(" Buy Now! ") == "buy now"
    assert _normalize("Click HERE.") == "click here"


def test_match_exact_phrase():
    assert _matched_bad_phrase("Buy Now") == "buy now"
    assert _matched_bad_phrase("Register") == "register"
    assert _matched_bad_phrase("Click Here!") == "click here"


def test_match_with_intensifier():
    assert _matched_bad_phrase("Get Started Today") == "get started"
    assert _matched_bad_phrase("Sign Up Now") == "sign up"


def test_no_match_when_rewritten():
    assert _matched_bad_phrase("Move into your dream home") is None
    assert _matched_bad_phrase("Next steps after viewing") is None  # 'next' not standalone
    assert _matched_bad_phrase("Register for the gala") is None     # extra context after


# ─── Finding-level integration ────────────────────────────────────────


def test_generic_button_text_flagged():
    html = (
        '<p><a style="background:#0a0;padding:10px;border-radius:4px" '
        'href="https://e.com/buy">Buy Now</a></p>'
    )
    f = asyncio.run(run(_email(html)))[0]
    assert f.passed is False
    assert f.severity.value == "MEDIUM"
    assert f.details["matched_pattern"] == "buy now"


def test_click_here_flagged():
    html = '<p><a href="https://e.com/x">Click here</a></p>'
    # 'Click here' matches CTA verb regex via no path? actually not in
    # the verb list — but bad-phrase check still runs on whatever lands
    # in cta_blocks. Force button styling so it lands in cta_blocks.
    html = (
        '<p><a style="background:#0a0;padding:10px" '
        'href="https://e.com/x">Click here</a></p>'
    )
    f = asyncio.run(run(_email(html)))[0]
    assert f.passed is False
    assert f.details["matched_pattern"] == "click here"


def test_outcome_copy_passes():
    html = (
        '<p><a style="background:#0a0;padding:12px;border-radius:4px" '
        'href="https://e.com/home">Move into your dream home</a></p>'
    )
    f = asyncio.run(run(_email(html)))[0]
    assert f.passed is True
    assert f.severity.value == "INFO"


def test_button_styled_preferred_as_primary():
    """Action-verb plain link first, button-styled second. Primary =
    button-styled regardless of order."""
    html = (
        '<p><a href="https://e.com/a">Register</a></p>'
        '<p><a style="background:#0a0;padding:10px" '
        'href="https://e.com/b">Reserve your spot at Lambton Mills</a></p>'
    )
    f = asyncio.run(run(_email(html)))[0]
    assert f.passed is True
    assert "Reserve your spot" in f.details["primary_cta_text"]


def test_no_cta_passes():
    html = "<p>Hi, just an update.</p>"
    f = asyncio.run(run(_email(html)))[0]
    assert f.passed is True


def test_unsub_styled_button_not_primary():
    """Styled unsub must not become the primary CTA inspected."""
    html = (
        '<p><a style="background:#ccc;padding:10px" '
        'href="https://e.com/unsubscribe">Unsubscribe</a></p>'
        '<p><a style="background:#0a0;padding:10px" '
        'href="https://e.com/buy">Buy Now</a></p>'
    )
    f = asyncio.run(run(_email(html)))[0]
    assert f.passed is False
    assert f.details["matched_pattern"] == "buy now"
