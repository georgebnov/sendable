"""AI-writing-pattern check.

Two signals: phrase fingerprint + sentence-length variance.
Tier logic: ≥3 phrases OR both signals → HIGH.
2 phrases alone, or low SD alone → MEDIUM. Else INFO PASS.
"""

from __future__ import annotations

import asyncio
import sys
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.copywriting.ai_writing_pattern import (  # noqa: E402
    _scan_phrases,
    _sentence_lengths,
    run,
)
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


# ─── Phrase scanner unit ─────────────────────────────────────────────


def test_scan_individual_phrases():
    assert "in conclusion" in _scan_phrases("In conclusion, the deal closed.")
    assert "delve into" in _scan_phrases("Let's delve into the details.")
    assert "navigate the" in _scan_phrases("We'll navigate the process for you.")
    assert "elevate your" in _scan_phrases("Time to elevate your portfolio.")


def test_leverage_verb_pattern():
    # Verb form (leverage + determiner).
    assert "leverage (verb)" in _scan_phrases("We leverage the platform daily.")
    # Noun form should not match.
    assert "leverage (verb)" not in _scan_phrases("They had competitive leverage here.")


def test_as_a_profession_understand():
    text = "As a real estate agent, I understand the pressure."
    assert "as a [profession] i understand" in _scan_phrases(text)


# ─── Sentence-length unit ────────────────────────────────────────────


def test_sentence_lengths_basic():
    text = "Hello world. This is longer text here! Short?"
    lens = _sentence_lengths(text)
    assert lens == [2, 5, 1]


# ─── Tier integration ───────────────────────────────────────────────


HUMAN_BURSTY = (
    "Hi Sarah,\n\n"
    "Quick one. The Lambton Mills unit you asked about is now listed. "
    "Pricing came in at $850,000 — under our walk-away number, which is "
    "a relief, especially given how every comparable in the area has "
    "drifted up in the last eight weeks.\n\n"
    "Tour Saturday? I can hold the 11am slot.\n\n"
    "Best,\nEmil"
)

AI_FLAT = (
    "Hi Sarah,\n\n"
    "I wanted to take a moment to reach out to you today. "
    "In today's market, it is important to note that pricing remains volatile. "
    "Feel free to reach out if you have any questions about your home. "
    "We are here to help you navigate the process from start to finish. "
    "Our team can leverage the latest data to elevate your portfolio. "
    "It's worth noting that we have many options for your needs. "
    "Don't hesitate to contact us for further information about listings. "
    "In conclusion, we look forward to working with you on this opportunity.\n\n"
    "Best,\nEmil"
)


def test_human_bursty_passes():
    f = asyncio.run(run(_email(HUMAN_BURSTY)))[0]
    assert f.passed is True


def test_ai_flat_text_high():
    f = asyncio.run(run(_email(AI_FLAT)))[0]
    assert f.passed is False
    # At minimum 3+ phrase hits → HIGH.
    assert f.severity.value == "HIGH"
    assert f.details["phrase_count"] >= 3


def test_two_phrases_alone_medium():
    text = (
        "Hi Sarah, the Bayview unit is on the market. "
        "Feel free to reach out with questions. "
        "Tour Saturday at 11am? Talk soon."
    )
    # Force a 2nd phrase deterministically.
    text = (
        "Hi Sarah, the Bayview unit just listed. "
        "Feel free to reach out about a tour. "
        "Let's navigate the offer together if you're interested. "
        "Saturday at 11am works."
    )
    f = asyncio.run(run(_email(text)))[0]
    assert f.details["phrase_count"] == 2
    # Variance not applicable (≤8 sentences) so the single signal is
    # phrase-only → MEDIUM.
    assert f.passed is False
    assert f.severity.value == "MEDIUM"


def test_low_variance_alone_medium():
    """≥8 sentences, low SD, 0 phrase hits → MEDIUM (variance only)."""
    # 8 sentences each ~6 words → SD near 0.
    body = (
        "Hi Sarah here is the unit update. "
        "The pricing came in at expected. "
        "The view from the balcony is great. "
        "The kitchen has been recently renovated. "
        "The location is near transit and shops. "
        "The maintenance fees are reasonable monthly. "
        "The building has a gym and pool. "
        "The unit faces south for sunlight."
    )
    f = asyncio.run(run(_email(body)))[0]
    assert f.details["variance_applicable"] is True
    assert f.details["low_variance"] is True
    assert f.details["phrase_count"] <= 1
    assert f.passed is False
    assert f.severity.value == "MEDIUM"


def test_clean_short_email_passes():
    body = "Hi Sarah, tour Saturday 11am works for me. Confirm and I'll set it."
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is True
    assert f.severity.value == "INFO"
