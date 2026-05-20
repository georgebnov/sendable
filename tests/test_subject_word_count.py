"""Subject word-count check.

Bands: ≤3 LOW, 4-10 INFO PASS, 11-14 MEDIUM, ≥15 MEDIUM.
Reply prefix (Re:/Fwd:) stripped before counting.
"""

from __future__ import annotations

import asyncio
import sys
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.copywriting.subject_word_count import (  # noqa: E402
    _count_words,
    _strip_reply_prefix,
    run,
)
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


# ─── Prefix-strip / count unit ─────────────────────────────────────────


def test_strip_single_re():
    assert _strip_reply_prefix("Re: Your listing tour") == "Your listing tour"


def test_strip_stacked_prefixes():
    assert _strip_reply_prefix("Re: Fwd: Re: Tour confirmed") == "Tour confirmed"


def test_strip_case_insensitive():
    assert _strip_reply_prefix("FW: details inside") == "details inside"


def test_no_prefix_unchanged():
    assert _strip_reply_prefix("New listings this week") == "New listings this week"


def test_count_skips_pure_punctuation():
    assert _count_words("Hi -- new home!") == 3


# ─── Band integration ─────────────────────────────────────────────────


def test_vague_short_subject_low():
    f = asyncio.run(run(_email("New home")))[0]
    assert f.passed is False
    assert f.severity.value == "LOW"
    assert f.details["words"] == 2


def test_borderline_short_passes():
    f = asyncio.run(run(_email("Lambton Mills tour Saturday")))[0]
    assert f.passed is True
    assert f.details["words"] == 4


def test_sweet_spot_passes():
    f = asyncio.run(run(_email("New homes at Lambton Mills opening this Saturday")))[0]
    assert f.passed is True
    assert f.severity.value == "INFO"
    assert 6 <= f.details["words"] <= 10


def test_wordy_subject_medium():
    subj = "We have a great new listing at Lambton Mills this Saturday afternoon"
    f = asyncio.run(run(_email(subj)))[0]
    assert f.passed is False
    assert f.severity.value == "MEDIUM"
    assert 11 <= f.details["words"] <= 14


def test_truncated_subject_medium():
    subj = (
        "A truly extraordinary opportunity has emerged this week for buyers "
        "looking at Lambton Mills new construction homes"
    )
    f = asyncio.run(run(_email(subj)))[0]
    assert f.passed is False
    assert f.severity.value == "MEDIUM"
    assert f.details["words"] >= 15


def test_reply_prefix_not_counted():
    """Re:/Fwd: must be stripped before counting — a 5-word subject with
    'Re:' prefix is still 5 words, not 6."""
    f = asyncio.run(run(_email("Re: Tour at Lambton Mills tomorrow")))[0]
    assert f.details["words"] == 5
    assert f.passed is True


def test_empty_subject_passes():
    f = asyncio.run(run(_email(None)))[0]
    assert f.passed is True
    assert f.severity.value == "INFO"
