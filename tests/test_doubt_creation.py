"""Doubt-creation phrase detection.

Any flagged phrase → MEDIUM.
No match → INFO PASS.
"no pressure" — only flagged in closing context (last 40% of body or P.S.).
"""

from __future__ import annotations

import asyncio
import sys
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.copywriting.doubt_creation import run  # noqa: E402
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


def test_if_you_are_still_unsure_flagged():
    body = "Hi Sarah, the unit is on the market. If you're still unsure, let me know.\n\nBest,\nEmil"
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is False
    assert f.severity.value == "MEDIUM"
    assert "if you're still unsure" in f.details["matches"]


def test_on_the_fence_flagged():
    body = "Hi Sarah, tour Saturday. If you're on the fence I get it.\n\nBest,\nEmil"
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is False
    assert "if you're on the fence" in f.details["matches"]


def test_its_up_to_you_flagged():
    body = "Hi Sarah, I have a slot Saturday. It's up to you whether to come.\n\nBest,\nEmil"
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is False


def test_no_pressure_in_ps_flagged():
    body = (
        "Hi Sarah, I have the floorplan ready. Saturday at 11am works.\n\n"
        "Best,\nEmil\n\n"
        "P.S. no pressure either way."
    )
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is False
    assert "no pressure (closing)" in f.details["matches"]


def test_no_pressure_in_closing_body_flagged():
    body = (
        "Hi Sarah, I have been tracking Lambton Mills launch for you. "
        "Pricing came in at $850,000 which lines up with what you asked "
        "for. The floorplan also matches what you were originally hoping "
        "to find. Tour Saturday at 11am works — no pressure.\n\n"
        "Best,\nEmil"
    )
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is False
    assert "no pressure (closing)" in f.details["matches"]


def test_no_pressure_early_in_body_not_flagged():
    """No-pressure used at opening (not closing context) → not flagged.
    Only the closing-context occurrence is doubt-creating per spec."""
    body = (
        "Hi Sarah, no pressure of course on this one, but I wanted to "
        "let you know the Lambton Mills launch this Saturday will have "
        "three units in your price range. Pricing matches the budget "
        "you mentioned. Tour Saturday at 11am?\n\n"
        "Best,\nEmil"
    )
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is True


def test_clean_body_passes():
    body = (
        "Hi Sarah, the Lambton Mills unit you asked about is on the "
        "market at $850,000. Tour Saturday?\n\nBest,\nEmil"
    )
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is True
    assert f.severity.value == "INFO"


def test_multiple_matches_collected():
    body = (
        "Hi Sarah, if you're still unsure, that's fine. "
        "If you're on the fence I get it. It's up to you.\n\n"
        "Best,\nEmil"
    )
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is False
    assert len(f.details["matches"]) >= 3
