"""Voice-consistency check.

≥80% dominant share → INFO PASS.
<80% → LOW advisory.
<4 total voice tokens → INFO PASS (skip).
"""

from __future__ import annotations

import asyncio
import sys
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.copywriting.voice_consistency import run  # noqa: E402
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


def test_pure_i_voice_passes():
    body = (
        "Hi Sarah,\n\n"
        "I have been tracking the Lambton Mills launch for you. "
        "I think the pricing matches what I told you to expect. "
        "I will hold a slot for you on Saturday morning. "
        "Let me know if I should confirm.\n\n"
        "Best,\nEmil"
    )
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is True
    assert f.details["dominant_voice"] == "I"
    assert f.details["dominant_share_pct"] >= 80


def test_pure_we_voice_passes():
    body = (
        "Hi Sarah,\n\n"
        "We have been tracking the Lambton Mills launch for you. "
        "We think the pricing matches what we told you to expect. "
        "We will hold a slot for you on Saturday. Our team can confirm "
        "Friday afternoon.\n\n"
        "Best,\nThe Team"
    )
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is True
    assert f.details["dominant_voice"] == "We"


def test_mixed_voice_advisory():
    body = (
        "Hi Sarah,\n\n"
        "I have been tracking Lambton Mills. We think the pricing fits. "
        "Our team will host a tour. I will confirm Friday. "
        "We can hold three slots if you and a friend want to come. "
        "I appreciate your patience.\n\n"
        "Best,\nEmil"
    )
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is False
    assert f.severity.value == "LOW"
    assert f.details["i_count"] >= 2
    assert f.details["we_count"] >= 2


def test_short_email_below_threshold_skips():
    body = "Hi Sarah, confirmed for Saturday. Talk soon."
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is True
    assert f.details["total"] < 4


def test_contractions_counted():
    body = (
        "Hi Sarah,\n\n"
        "I'm holding a slot for you Saturday. "
        "I've checked the floorplan. I'll send the deck Friday. "
        "I'd love your read on the pricing.\n\n"
        "Best,\nEmil"
    )
    f = asyncio.run(run(_email(body)))[0]
    assert f.details["i_count"] >= 4
    assert f.passed is True
