"""Personalization depth check.

Bands:
  ≥1 contextual signal in subject/preheader/body → INFO PASS.
  No signal + named greeting                     → MEDIUM (first-name only).
  No signal + generic greeting / no greeting     → HIGH.
"""

from __future__ import annotations

import asyncio
import sys
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.industry.real_estate.personalization_depth import run  # noqa: E402
from audit.parse import ParsedEmail  # noqa: E402


def _email(plain: str, subject: str = "Update") -> ParsedEmail:
    msg = EmailMessage()
    msg["From"] = "Emil <emil@b.com>"
    msg["Subject"] = subject
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
        subject=subject,
        authentication_results=[],
    )


# ─── PASS — contextual signals ───────────────────────────────────────


def test_property_type_signal_passes():
    body = "Hi Sarah,\n\nA new pre-construction townhouse just hit the market.\n\nBest,\nEmil"
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is True
    assert "property_type" in f.details["signals"]


def test_price_signal_passes():
    body = "Hi Sarah,\n\nFound a place in your budget at $850,000.\n\nBest,\nEmil"
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is True
    assert "price_or_money" in f.details["signals"]


def test_behavioural_trigger_passes():
    body = (
        "Hi Sarah,\n\nSince you viewed the Bayview unit last week, three "
        "comparable listings dropped today.\n\nBest,\nEmil"
    )
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is True
    assert "behavioural_trigger" in f.details["signals"]


def test_address_signal_passes():
    body = "Hi Sarah,\n\nTour at 142 Lambton Avenue this Saturday.\n\nBest,\nEmil"
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is True
    assert "address_or_intersection" in f.details["signals"]


def test_intersection_signal_passes():
    body = "Hi Sarah,\n\nNew building at Bloor and Bathurst opened pricing today.\n\nBest,\nEmil"
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is True
    assert "address_or_intersection" in f.details["signals"]


def test_signal_in_subject_counts():
    body = "Hi Sarah,\n\nUpdate inside.\n\nBest,\nEmil"
    f = asyncio.run(run(_email(body, subject="Penthouse listings this week")))[0]
    assert f.passed is True


# ─── MEDIUM — first name only ─────────────────────────────────────────


def test_first_name_only_medium():
    body = "Hi Sarah,\n\nQuick update for you this week.\n\nBest,\nEmil"
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is False
    assert f.severity.value == "MEDIUM"
    assert f.details["greeting_names_person"] is True


# ─── HIGH — generic / no greeting ────────────────────────────────────


def test_generic_greeting_no_signal_high():
    body = "Dear Customer,\n\nQuick update for you this week.\n\nBest,\nEmil"
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is False
    assert f.severity.value == "HIGH"


def test_dear_homeowner_no_signal_high():
    body = "Dear Homeowner,\n\nWe have news for you.\n\nBest,\nEmil"
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is False
    assert f.severity.value == "HIGH"


def test_hi_there_no_signal_high():
    body = "Hi there,\n\nQuick update.\n\nBest,\nEmil"
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is False
    assert f.severity.value == "HIGH"


def test_no_greeting_no_signal_high():
    body = "Quick update inside this week.\n\nBest,\nEmil"
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is False
    assert f.severity.value == "HIGH"
