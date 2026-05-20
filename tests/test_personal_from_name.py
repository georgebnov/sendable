"""Personal-name From: display check.

Flag tokens (Realty, Group, Properties, …) or handle words (Info,
Support, …) in display name → LOW advisory.
First-name merge tag → PASS.
Non-first-name merge tag → LOW advisory.
"""

from __future__ import annotations

import asyncio
import sys
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.copywriting.personal_from_name import run  # noqa: E402
from audit.parse import ParsedEmail  # noqa: E402


def _email(from_addr: str) -> ParsedEmail:
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["Subject"] = "x"
    msg.set_content("body", subtype="plain")
    headers: dict[str, list[str]] = {}
    for k, v in msg.items():
        headers.setdefault(k.lower(), []).append(str(v))
    return ParsedEmail(
        raw=msg,
        headers=headers,
        html=None,
        plain_text="body",
        from_addr=from_addr,
        to_addrs=[],
        subject="x",
        authentication_results=[],
    )


# ─── PASS cases ──────────────────────────────────────────────────────


def test_personal_name_passes():
    f = asyncio.run(run(_email('"Emil Babakhanov" <emil@lambton.com>')))[0]
    assert f.passed is True
    assert f.severity.value == "INFO"


def test_first_name_jinja_placeholder_passes():
    f = asyncio.run(run(_email('"{{first_name}}" <newsletter@lambton.com>')))[0]
    assert f.passed is True
    assert "{{first_name}}" in f.details["placeholders"]


def test_first_name_bracket_placeholder_passes():
    f = asyncio.run(run(_email('"[FIRST NAME GOES HERE]" <a@b.com>')))[0]
    assert f.passed is True


def test_first_name_mailchimp_placeholder_passes():
    f = asyncio.run(run(_email('"*|FNAME|*" <a@b.com>')))[0]
    assert f.passed is True


# ─── FAIL — token matches ───────────────────────────────────────────


def test_realty_group_flagged():
    f = asyncio.run(run(_email('"Lambton Realty Group" <a@b.com>')))[0]
    assert f.passed is False
    assert f.severity.value == "LOW"
    assert {"realty", "group"} <= set(f.details["matches"])


def test_real_estate_phrase_flagged():
    f = asyncio.run(run(_email('"Acme Real Estate" <a@b.com>')))[0]
    assert f.passed is False
    assert "real estate" in f.details["matches"]


def test_legal_suffix_flagged():
    f = asyncio.run(run(_email('"Acme Inc" <a@b.com>')))[0]
    assert f.passed is False
    assert "inc" in f.details["matches"]


def test_co_dot_flagged():
    f = asyncio.run(run(_email('"Acme & Co." <a@b.com>')))[0]
    assert f.passed is False
    assert "co." in f.details["matches"]


def test_handle_display_flagged():
    f = asyncio.run(run(_email('"Info" <info@lambton.com>')))[0]
    assert f.passed is False
    assert any(h.startswith("handle:") for h in f.details["matches"])


# ─── FAIL — wrong placeholder ───────────────────────────────────────


def test_non_first_name_placeholder_flagged():
    f = asyncio.run(run(_email('"{{company_name}}" <a@b.com>')))[0]
    assert f.passed is False
    assert "{{company_name}}" in f.details["placeholders"]


# ─── Edge: no display name ──────────────────────────────────────────


def test_no_display_name_passes():
    """Raw address with no display name has nothing to grade — INFO PASS.
    The spec narrowly bands LOW on token / placeholder / handle hits."""
    f = asyncio.run(run(_email("emil@lambton.com")))[0]
    assert f.passed is True
