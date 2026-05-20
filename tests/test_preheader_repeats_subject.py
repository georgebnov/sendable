"""Preheader vs subject token-overlap check.

≥60% overlap of subject tokens in preheader (first 100 chars) → LOW.
<60% overlap → INFO PASS.
Missing subject or preheader → INFO PASS (skip).
"""

from __future__ import annotations

import asyncio
import sys
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.copywriting.preheader_repeats_subject import run  # noqa: E402
from audit.parse import ParsedEmail  # noqa: E402


def _email(subject: str, preheader: str | None) -> ParsedEmail:
    body = "Body content here."
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
    msg["Subject"] = subject
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
        subject=subject,
        authentication_results=[],
    )


def test_verbatim_repeat_flagged():
    subj = "New homes at Lambton Mills launch Saturday"
    f = asyncio.run(run(_email(subj, subj)))[0]
    assert f.passed is False
    assert f.severity.value == "LOW"
    assert f.details["overlap_pct"] == 100.0


def test_partial_repeat_above_threshold_flagged():
    subj = "Lambton Mills launch Saturday at noon"  # 5 tokens
    pre = "Lambton Mills launch Saturday — be there"  # shares 4/5 = 80%
    f = asyncio.run(run(_email(subj, pre)))[0]
    assert f.passed is False
    assert f.details["overlap_pct"] >= 60


def test_complementary_preheader_passes():
    subj = "Lambton Mills launches"  # 3 tokens
    pre = "Pricing locked through May plus floorplans inside"
    f = asyncio.run(run(_email(subj, pre)))[0]
    assert f.passed is True
    assert f.details["overlap_pct"] < 60


def test_overlap_only_counted_in_first_100_chars():
    """Subject tokens appearing past the 100-char window don't push
    overlap up."""
    subj = "Lambton Mills launch"  # 3 tokens
    pre = (
        "Pricing locked through May plus floorplans inside — also a few "
        "buyer FAQs included for those who missed the prior "
        "Lambton Mills launch communication"
    )
    f = asyncio.run(run(_email(subj, pre)))[0]
    # First 100 chars contain none of "lambton", "mills", "launch".
    assert f.passed is True


def test_missing_preheader_skips():
    f = asyncio.run(run(_email("Lambton Mills launches", None)))[0]
    assert f.passed is True
    assert f.severity.value == "INFO"


def test_empty_subject_skips():
    f = asyncio.run(run(_email("", "Pricing locked plus floorplans inside.")))[0]
    assert f.passed is True
