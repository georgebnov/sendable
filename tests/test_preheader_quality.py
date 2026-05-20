"""Preheader / preview-text quality check.

HIGH FAIL: absent, <20 chars, or artifact substring match.
INFO PASS: present, ≥20 chars, no artifact.
"""

from __future__ import annotations

import asyncio
import sys
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.copywriting.preheader_quality import run  # noqa: E402
from audit.parse import ParsedEmail  # noqa: E402


def _email_with_preheader(preheader: str | None, body: str = "Body content here.") -> ParsedEmail:
    if preheader is None:
        html = f"<html><body><p>{body}</p></body></html>"
    else:
        html = (
            "<html><body>"
            f'<div style="display:none;font-size:1px;color:#fff;">{preheader}</div>'
            f"<p>{body}</p></body></html>"
        )
    msg = EmailMessage()
    msg["From"] = "Emil <emil@b.com>"
    msg["Subject"] = "x"
    msg.set_content(body, subtype="plain")
    msg.add_alternative(html, subtype="html")
    headers: dict[str, list[str]] = {}
    for k, v in msg.items():
        headers.setdefault(k.lower(), []).append(str(v))
    return ParsedEmail(
        raw=msg,
        headers=headers,
        html=html,
        plain_text=body,
        from_addr="Emil <emil@b.com>",
        to_addrs=[],
        subject="x",
        authentication_results=[],
    )


def test_intentional_preheader_passes():
    f = asyncio.run(run(_email_with_preheader(
        "Pricing locked for the Lambton Mills launch this Saturday."
    )))[0]
    assert f.passed is True
    assert f.severity.value == "INFO"


def test_absent_preheader_flagged():
    f = asyncio.run(run(_email_with_preheader(None)))[0]
    assert f.passed is False
    assert f.severity.value == "HIGH"


def test_short_preheader_flagged():
    f = asyncio.run(run(_email_with_preheader("Hi there")))[0]
    assert f.passed is False
    assert f.details["chars"] < 20


def test_view_in_browser_artifact_flagged():
    f = asyncio.run(run(_email_with_preheader(
        "View in browser — having trouble seeing this?"
    )))[0]
    assert f.passed is False
    assert "view in browser" in f.details["matches"]
    assert "having trouble" in f.details["matches"]


def test_cant_see_this_artifact_flagged():
    f = asyncio.run(run(_email_with_preheader(
        "Can't see this email? Open in browser."
    )))[0]
    assert f.passed is False
    assert "can't see this" in f.details["matches"]


def test_click_here_to_view_artifact_flagged():
    f = asyncio.run(run(_email_with_preheader(
        "Click here to view this message in your browser"
    )))[0]
    assert f.passed is False
    assert "click here to view" in f.details["matches"]


def test_unsubscribe_opening_flagged():
    f = asyncio.run(run(_email_with_preheader(
        "Unsubscribe from these messages anytime"
    )))[0]
    assert f.passed is False
    assert "unsubscribe-opening" in f.details["matches"]


def test_unsubscribe_late_in_preheader_does_not_flag():
    """'unsubscribe' deep in a long preheader (footer fallback) is
    artifact-y but the spec only flags opening occurrence. Other
    artifact patterns may also fire; check unsubscribe-opening absent."""
    pre = "Pricing locked for Lambton Mills launch — reply for unsubscribe info"
    f = asyncio.run(run(_email_with_preheader(pre)))[0]
    assert "unsubscribe-opening" not in (f.details.get("matches") or [])
