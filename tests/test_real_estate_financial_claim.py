"""Real-estate predatory-scheme phrase detection.

Any flagged phrase → HIGH.
No match → INFO PASS.
"""

from __future__ import annotations

import asyncio
import sys
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.industry.real_estate.financial_claim import run  # noqa: E402
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


def test_we_buy_houses_flagged():
    f = asyncio.run(run(_email("We buy houses in any condition.")))[0]
    assert f.passed is False
    assert f.severity.value == "HIGH"
    assert "we buy houses" in f.details["matches"]


def test_guaranteed_sale_flagged():
    f = asyncio.run(run(_email("Get a guaranteed sale this month.")))[0]
    assert f.passed is False
    assert "guaranteed sale" in f.details["matches"]


def test_instant_cash_offer_flagged():
    f = asyncio.run(run(_email("Click for an instant cash offer today.")))[0]
    assert f.passed is False


def test_as_is_cash_flagged():
    f = asyncio.run(run(_email("We pay as-is cash for your home.")))[0]
    assert f.passed is False
    assert "as-is cash" in f.details["matches"]


def test_cash_in_n_days_flagged():
    f = asyncio.run(run(_email("Receive cash in 7 days, no hassle.")))[0]
    assert f.passed is False
    assert "cash in N days" in f.details["matches"]


def test_sell_in_n_days_guaranteed_flagged():
    f = asyncio.run(run(_email("We will sell in 14 days guaranteed.")))[0]
    assert f.passed is False
    assert "sell in N days guaranteed" in f.details["matches"]


def test_close_in_n_days_with_guarantee_flagged():
    f = asyncio.run(run(_email(
        "We can close in 7 days — guaranteed turnaround."
    )))[0]
    assert f.passed is False
    assert "close in N days + guarantee" in f.details["matches"]


def test_close_in_n_days_without_guarantee_passes():
    """Legitimate closing-window commentary without the guarantee
    pairing must not fire — agents discuss closing windows constantly."""
    f = asyncio.run(run(_email(
        "Most offers close in 30 days under standard financing terms."
    )))[0]
    assert f.passed is True


def test_clean_body_passes():
    f = asyncio.run(run(_email(
        "Hi Sarah, the Lambton Mills unit you asked about hit the "
        "market this morning at $850,000. Tour Saturday?"
    )))[0]
    assert f.passed is True
    assert f.severity.value == "INFO"


def test_multiple_matches_collected():
    f = asyncio.run(run(_email(
        "We buy houses — instant cash offer, guaranteed sale!"
    )))[0]
    assert f.passed is False
    assert len(f.details["matches"]) >= 3
