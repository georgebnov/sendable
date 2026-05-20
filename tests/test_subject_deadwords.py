"""Subject deadwords check.

Flag list: newsletter, update, digest, roundup, weekly, monthly, edition, issue.
Any present → MEDIUM. None → INFO PASS.
"""

from __future__ import annotations

import asyncio
import sys
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.copywriting.subject_deadwords import run  # noqa: E402
from audit.parse import ParsedEmail  # noqa: E402


def _email(subject: str | None) -> ParsedEmail:
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    if subject is not None:
        msg["Subject"] = subject
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


def test_newsletter_flagged():
    f = asyncio.run(run(_email("Your weekly newsletter is here")))[0]
    assert f.passed is False
    assert f.severity.value == "MEDIUM"
    assert "newsletter" in f.details["matches"]
    assert "weekly" in f.details["matches"]


def test_update_flagged():
    f = asyncio.run(run(_email("Market update for May")))[0]
    assert f.passed is False
    assert "update" in f.details["matches"]


def test_each_deadword_flagged():
    for word in ("digest", "roundup", "weekly", "monthly", "edition", "issue"):
        f = asyncio.run(run(_email(f"Title with {word} inside")))[0]
        assert f.passed is False, word
        assert word in f.details["matches"], word


def test_case_insensitive():
    f = asyncio.run(run(_email("MONTHLY ROUNDUP")))[0]
    assert f.passed is False
    assert {"monthly", "roundup"} <= set(f.details["matches"])


def test_clean_subject_passes():
    f = asyncio.run(run(_email("Lambton Mills launch this Saturday")))[0]
    assert f.passed is True
    assert f.severity.value == "INFO"


def test_word_boundary_not_substring():
    """Don't match deadword inside a longer word (e.g. 'reissue', 'updated')."""
    f = asyncio.run(run(_email("Reissued certificate of updated documents")))[0]
    assert f.passed is True


def test_empty_subject_passes():
    f = asyncio.run(run(_email(None)))[0]
    assert f.passed is True
