"""Long-paragraph check.

Worst-paragraph word count drives the band.
≤60 words → INFO PASS. 61-100 → MEDIUM. >100 → HIGH.
"""

from __future__ import annotations

import asyncio
import sys
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.copywriting.long_paragraph import run  # noqa: E402
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


def _para(n_words: int) -> str:
    return " ".join(["word"] * n_words)


def test_short_paragraphs_pass():
    body = (
        f"Hi Sarah,\n\n{_para(30)}\n\n{_para(25)}\n\n"
        f"Best,\nEmil"
    )
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is True
    assert f.severity.value == "INFO"


def test_medium_paragraph_flagged():
    body = (
        f"Hi Sarah,\n\n{_para(75)}\n\n"
        f"Best,\nEmil"
    )
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is False
    assert f.severity.value == "MEDIUM"
    assert f.details["worst_words"] == 75
    assert f.details["worst_lines_est"] == 7  # 75/12 → 7


def test_high_paragraph_flagged():
    body = (
        f"Hi Sarah,\n\n{_para(130)}\n\n"
        f"Best,\nEmil"
    )
    f = asyncio.run(run(_email(body)))[0]
    assert f.passed is False
    assert f.severity.value == "HIGH"
    assert f.details["worst_words"] == 130


def test_worst_paragraph_drives_band():
    """One short + one HIGH paragraph → HIGH overall."""
    body = (
        f"Hi Sarah,\n\n{_para(20)}\n\n{_para(120)}\n\n"
        f"Best,\nEmil"
    )
    f = asyncio.run(run(_email(body)))[0]
    assert f.severity.value == "HIGH"


def test_ps_counted():
    body = (
        f"Hi Sarah,\n\n{_para(30)}\n\nBest,\nEmil\n\n"
        f"P.S. {_para(110)}"
    )
    f = asyncio.run(run(_email(body)))[0]
    assert f.severity.value == "HIGH"
