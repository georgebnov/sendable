"""Fake Re:/Fwd: subject-prefix check.

HIGH + hard_gate when Re:/Fwd: prefix is present without In-Reply-To
or References. INFO PASS when prefix has matching thread headers or
no prefix at all.
"""

from __future__ import annotations

import asyncio
import sys
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.copywriting.fake_reply_subject import run  # noqa: E402
from audit.parse import ParsedEmail  # noqa: E402


def _email(
    subject: str | None,
    *,
    in_reply_to: str | None = None,
    references: str | None = None,
) -> ParsedEmail:
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    if subject is not None:
        msg["Subject"] = subject
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
    if references:
        msg["References"] = references
    msg.set_content("body", subtype="plain")
    headers: dict[str, list[str]] = {}
    for k, v in msg.items():
        headers.setdefault(k.lower(), []).append(str(v))
    return ParsedEmail(
        raw=msg,
        headers=headers,
        html=None,
        plain_text="body",
        from_addr="sender@example.com",
        to_addrs=[],
        subject=subject,
        authentication_results=[],
    )


def test_re_without_thread_headers_flagged():
    f = asyncio.run(run(_email("Re: Your offer on Lambton Mills")))[0]
    assert f.passed is False
    assert f.severity.value == "HIGH"
    assert f.hard_gate is True
    assert f.details["prefix"] == "re"


def test_fwd_without_thread_headers_flagged():
    f = asyncio.run(run(_email("Fwd: Important update")))[0]
    assert f.passed is False
    assert f.hard_gate is True
    assert f.details["prefix"] == "fwd"


def test_fw_short_form_flagged():
    f = asyncio.run(run(_email("FW: tour details")))[0]
    assert f.passed is False
    assert f.details["prefix"] == "fw"


def test_re_with_in_reply_to_passes():
    f = asyncio.run(run(_email(
        "Re: Your offer",
        in_reply_to="<abc123@example.com>",
    )))[0]
    assert f.passed is True
    assert f.severity.value == "INFO"
    assert "in-reply-to" in f.details["thread_headers_present"]


def test_re_with_references_passes():
    f = asyncio.run(run(_email(
        "Re: Your offer",
        references="<abc@example.com> <def@example.com>",
    )))[0]
    assert f.passed is True
    assert "references" in f.details["thread_headers_present"]


def test_no_prefix_passes():
    f = asyncio.run(run(_email("New listing at Lambton Mills")))[0]
    assert f.passed is True


def test_empty_subject_passes():
    f = asyncio.run(run(_email(None)))[0]
    assert f.passed is True


def test_case_insensitive_prefix():
    f = asyncio.run(run(_email("rE: spoofed")))[0]
    assert f.passed is False
    assert f.details["prefix"] == "re"
