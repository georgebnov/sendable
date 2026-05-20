"""From-name vs sign-off consistency check.

Full / first-name / initials match in sign-off region → INFO PASS.
No match → MEDIUM FAIL.
Empty display or all-placeholder display → INFO PASS (skip).
"""

from __future__ import annotations

import asyncio
import sys
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.copywriting.from_name_body_consistency import run  # noqa: E402
from audit.parse import ParsedEmail  # noqa: E402


def _email(from_addr: str, plain: str) -> ParsedEmail:
    msg = EmailMessage()
    msg["From"] = from_addr
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
        from_addr=from_addr,
        to_addrs=[],
        subject="x",
        authentication_results=[],
    )


def test_full_name_in_signature_passes():
    body = (
        "Hi Sarah,\n\n"
        "Quick update on Lambton Mills — pricing locked.\n\n"
        "Best,\nEmil Babakhanov"
    )
    f = asyncio.run(run(_email('"Emil Babakhanov" <emil@b.com>', body)))[0]
    assert f.passed is True
    assert f.details["match_kind"] == "full"


def test_first_name_only_in_signature_passes():
    body = (
        "Hi Sarah,\n\n"
        "Tour Saturday confirmed.\n\n"
        "Talk soon,\nEmil"
    )
    f = asyncio.run(run(_email('"Emil Babakhanov" <emil@b.com>', body)))[0]
    assert f.passed is True
    assert f.details["match_kind"] == "partial"
    assert "emil" in f.details["tokens"]


def test_initials_match_passes():
    body = (
        "Hi Sarah,\n\n"
        "Update inside.\n\n"
        "— EB"
    )
    f = asyncio.run(run(_email('"Emil Babakhanov" <emil@b.com>', body)))[0]
    assert f.passed is True
    assert f.details["match_kind"] == "initials"


def test_missing_name_in_signoff_flagged():
    body = (
        "Hi Sarah,\n\n"
        "Update on the Bayview unit.\n\n"
        "Best,\nThe Sales Team"
    )
    f = asyncio.run(run(_email('"Emil Babakhanov" <emil@b.com>', body)))[0]
    assert f.passed is False
    assert f.severity.value == "MEDIUM"


def test_empty_display_skips():
    body = "Hi,\n\nUpdate.\n\nBest,\nEmil"
    f = asyncio.run(run(_email("emil@b.com", body)))[0]
    assert f.passed is True
    assert f.severity.value == "INFO"


def test_placeholder_display_skips():
    body = "Hi,\n\nUpdate.\n\nBest,\nEmil"
    f = asyncio.run(run(_email('"{{first_name}}" <a@b.com>', body)))[0]
    assert f.passed is True


def test_name_in_body_tail_passes_when_no_signature_block():
    """Sender name in last 200 chars even without a detected signature
    block (no 'Best,' / 'Cheers,' etc.) still counts."""
    body = "Just letting you know — Emil"
    f = asyncio.run(run(_email('"Emil Babakhanov" <emil@b.com>', body)))[0]
    assert f.passed is True


def test_stopword_token_does_not_create_false_match():
    """Display name 'The Team' has all stopword tokens; sign-off must not
    spuriously pass on 'the' or 'team' alone in unrelated body text."""
    body = "Hi,\n\nThe market is hot.\n\nBest,\nAnother Person"
    f = asyncio.run(run(_email('"The Team" <a@b.com>', body)))[0]
    assert f.passed is False
