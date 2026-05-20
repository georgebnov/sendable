"""Generic-opener check tests.

Flagged phrases in first 120 chars of body lead → MEDIUM.
Clean opener → INFO PASS.
Empty body → INFO PASS.
"""

from __future__ import annotations

import asyncio
import sys
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.copywriting.generic_opener import run  # noqa: E402
from audit.parse import ParsedEmail  # noqa: E402


def _email(plain: str) -> ParsedEmail:
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["Subject"] = "Test"
    msg.set_content(plain, subtype="plain")
    headers: dict[str, list[str]] = {}
    for k, v in msg.items():
        headers.setdefault(k.lower(), []).append(str(v))
    return ParsedEmail(
        raw=msg,
        headers=headers,
        html=None,
        plain_text=plain,
        from_addr="sender@example.com",
        to_addrs=[],
        subject="Test",
        authentication_results=[],
    )


def test_flags_hope_this_email_finds_you():
    body = "Hi Sarah,\n\nI hope this email finds you well. Quick update on the listing.\n\nBest,\nEmil"
    findings = asyncio.run(run(_email(body)))
    assert len(findings) == 1
    f = findings[0]
    assert f.passed is False
    assert f.severity.value == "MEDIUM"
    assert "i hope this email finds you" in f.details["matches"]


def test_flags_just_following_up():
    body = "Hi,\n\nJust following up on my note from last week.\n\nThanks,\nEmil"
    findings = asyncio.run(run(_email(body)))
    assert findings[0].passed is False
    assert "just following up" in findings[0].details["matches"]


def test_flags_to_whom_it_may_concern():
    body = "To whom it may concern,\n\nWe have a unit opening.\n\nRegards,\nEmil"
    findings = asyncio.run(run(_email(body)))
    assert findings[0].passed is False


def test_flags_dear_valued():
    body = "Dear Valued Client,\n\nNew listings inside.\n\nBest,\nEmil"
    findings = asyncio.run(run(_email(body)))
    assert findings[0].passed is False
    assert "dear valued" in findings[0].details["matches"]


def test_clean_specific_opener_passes():
    body = (
        "Hi Sarah,\n\n"
        "The Lambton Mills unit you asked about hit the market this morning.\n\n"
        "Best,\nEmil"
    )
    findings = asyncio.run(run(_email(body)))
    assert len(findings) == 1
    assert findings[0].passed is True
    assert findings[0].severity.value == "INFO"


def test_phrase_outside_window_ignored():
    """Flag phrase past 120 chars of lead must not trip the check."""
    pad = "Quick note on the Bayview listing that just dropped. "  # ~50 chars
    body = (
        "Hi,\n\n"
        + pad * 3
        + "I hope this email finds you well.\n\n"  # now well past 120 chars
        "Best,\nEmil"
    )
    findings = asyncio.run(run(_email(body)))
    assert findings[0].passed is True


def test_empty_body_passes():
    findings = asyncio.run(run(_email("")))
    assert findings[0].passed is True
    assert findings[0].severity.value == "INFO"
