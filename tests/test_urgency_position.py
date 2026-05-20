"""Urgency-position check.

Urgency in first 40% of body → MEDIUM.
Urgency only in last 60% → INFO PASS.
No urgency at all → INFO PASS.
"""

from __future__ import annotations

import asyncio
import sys
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.copywriting.urgency_position import run  # noqa: E402
from audit.parse import ParsedEmail  # noqa: E402


def _email(plain: str) -> ParsedEmail:
    msg = EmailMessage()
    msg["From"] = "Emil <emil@b.com>"
    msg["Subject"] = "x"
    msg.set_content(plain, subtype="plain")
    headers: dict[str, list[str]] = {}
    for k, v in msg.items():
        headers.setdefault(k.lower(), []).append(str(v))
    return ParsedEmail(
        raw=msg,
        headers=headers,
        html=None,
        plain_text=plain,
        from_addr="Emil <emil@b.com>",
        to_addrs=[],
        subject="x",
        authentication_results=[],
    )


def test_urgency_at_open_flagged():
    body = (
        "Hi Sarah,\n\n"
        "Act now — limited time offer. "
        "The Lambton Mills launch is something I've been tracking for you. "
        "Pricing looks favourable. Tour Saturday?\n\n"
        "Best,\nEmil"
    )
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is False
    assert f.severity.value == "MEDIUM"
    labels = {h["phrase"] for h in f.details["front_hits"]}
    assert "act now" in labels
    assert "limited time" in labels


def test_urgency_at_close_passes():
    body = (
        "Hi Sarah,\n\n"
        "The Lambton Mills launch is something I have been tracking for "
        "you over the past several months. Pricing looks favourable and "
        "the floorplans match what you were originally hoping to find. "
        "Three units in your price range opened today. I think it is "
        "worth a tour this weekend if you are available.\n\n"
        "Tour Saturday at 11am — spots left fill quickly so reply by "
        "Friday to lock the slot.\n\n"
        "Best,\nEmil"
    )
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is True
    assert any(h["phrase"] == "spots left" for h in f.details["late_hits"])


def test_no_urgency_passes():
    body = (
        "Hi Sarah,\n\nThe Lambton Mills unit you asked about is now "
        "listed at $850,000. Tour Saturday?\n\nBest,\nEmil"
    )
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is True
    assert f.severity.value == "INFO"


def test_deadline_in_first_40_pct_flagged():
    body = (
        "Hi Sarah,\n\n"
        "Deadline is Friday. "
        "We have a great unit at Lambton Mills with the floorplan you "
        "asked about, priced at $850,000. Let me know if you would like "
        "to schedule a viewing this weekend.\n\n"
        "Best,\nEmil"
    )
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is False
    assert any(h["phrase"] == "deadline" for h in f.details["front_hits"])


def test_ps_urgency_treated_as_late():
    body = (
        "Hi Sarah,\n\nThe Lambton Mills launch this Saturday will have "
        "three units in your price range. Pricing came in at $850,000 "
        "which lines up with the budget you mentioned. Tour Saturday?\n\n"
        "Best,\nEmil\n\n"
        "P.S. Last chance to lock the early-bird floorplan."
    )
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is True
    assert any(h["phrase"] == "last chance" for h in f.details.get("late_hits", []))
