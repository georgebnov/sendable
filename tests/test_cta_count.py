"""CTA-count check tests.

Counted: action-verb anchors + button-styled anchors (from
StructuredEmail.cta_blocks). Excluded: unsubscribe, view-in-browser,
manage-preferences (chrome, not asks).

Bands: 0-1 INFO PASS, 2 MEDIUM, 3+ HIGH.
"""

from __future__ import annotations

import asyncio
import sys
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.copywriting.cta_count import run  # noqa: E402
from audit.parse import ParsedEmail  # noqa: E402


def _email(html: str) -> ParsedEmail:
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["Subject"] = "Test"
    msg.set_content("plain fallback", subtype="plain")
    msg.add_alternative(html, subtype="html")
    headers: dict[str, list[str]] = {}
    for k, v in msg.items():
        headers.setdefault(k.lower(), []).append(str(v))
    return ParsedEmail(
        raw=msg,
        headers=headers,
        html=html,
        plain_text="plain fallback",
        from_addr="sender@example.com",
        to_addrs=[],
        subject="Test",
        authentication_results=[],
    )


def test_zero_cta_passes():
    html = "<p>Hi, here is the update. Nothing to click.</p>"
    f = asyncio.run(run(_email(html)))[0]
    assert f.passed is True
    assert f.details["count"] == 0


def test_one_cta_passes():
    html = '<p>Update here.</p><p><a href="https://e.com/r">Register</a></p>'
    f = asyncio.run(run(_email(html)))[0]
    assert f.passed is True
    assert f.details["count"] == 1
    assert f.severity.value == "INFO"


def test_two_ctas_medium():
    html = (
        '<p><a href="https://e.com/r">Register</a></p>'
        '<p><a href="https://e.com/d">Download the guide</a></p>'
    )
    f = asyncio.run(run(_email(html)))[0]
    assert f.passed is False
    assert f.severity.value == "MEDIUM"
    assert f.details["count"] == 2


def test_three_ctas_high():
    html = (
        '<p><a href="https://e.com/r">Register</a></p>'
        '<p><a href="https://e.com/d">Download the guide</a></p>'
        '<p><a href="https://e.com/b">Book a tour</a></p>'
    )
    f = asyncio.run(run(_email(html)))[0]
    assert f.passed is False
    assert f.severity.value == "HIGH"
    assert f.details["count"] == 3


def test_unsubscribe_link_excluded():
    """Passive nav anchors must not count toward CTA total."""
    html = (
        '<p><a href="https://e.com/r">Register</a></p>'
        '<p><a href="https://e.com/unsubscribe">Unsubscribe</a></p>'
        '<p><a href="https://e.com/view">View in browser</a></p>'
    )
    f = asyncio.run(run(_email(html)))[0]
    assert f.details["count"] == 1
    assert f.passed is True


def test_styled_unsubscribe_button_excluded():
    """ESP-styled unsub button has button shape but is still passive."""
    html = (
        '<p><a href="https://e.com/r">Register</a></p>'
        '<p><a style="background:#ccc;padding:10px" '
        'href="https://e.com/unsubscribe">Manage preferences</a></p>'
    )
    f = asyncio.run(run(_email(html)))[0]
    assert f.details["count"] == 1


def test_button_styled_non_verb_counts():
    """Anchor with button styling but no action verb in text still counts —
    it is button-shaped which signals 'click me' regardless of wording."""
    html = (
        '<p><a style="background:#0a0;padding:12px;border-radius:4px" '
        'href="https://e.com/listing">View listings</a></p>'
        '<p><a style="background:#0a0;padding:12px;border-radius:4px" '
        'href="https://e.com/tour">Schedule a tour</a></p>'
    )
    f = asyncio.run(run(_email(html)))[0]
    assert f.details["count"] == 2
    assert f.severity.value == "MEDIUM"
