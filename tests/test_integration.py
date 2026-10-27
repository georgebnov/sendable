"""The whole chain: store a sender's sends, then catch a regression in the next one.

This is the only test that proves the store earns its place. A drift check is
worthless without history, and history is worthless if the store cannot write and
read it back in the shape the checks expect. Everything in between is covered by
narrower tests; this one proves the pieces connect.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path

import pytest

from engine.parse import ParsedEmail, parse_eml
from engine.report import Finding, Report
from engine.runner import audit
from store import Store


def _sent_at(n: int) -> str:
    """An RFC 5322 date for send `n`, placed inside the 30-day drift window.

    The drift checks compare a stored row's `received_at` against `now`, so a
    hard-coded calendar date silently leaves the window as real time passes and
    the test starts failing for a reason the code did not cause. Send 1 is the
    oldest; each later send is one day newer.
    """
    return format_datetime(datetime.now(UTC) - timedelta(days=20 - n))


def _send(
    n: int,
    *,
    spf: str = "pass",
    dkim: str = "pass",
    dmarc: str = "pass",
    policy: str = "REJECT",
    display: str = "Jane Okafor",
    reply_to: str | None = None,
) -> ParsedEmail:
    """One bulk send from jane@example.com, with the authentication it reported."""
    reply = f"Reply-To: {reply_to}\r\n" if reply_to else ""
    return parse_eml(
        f"From: {display} <jane@example.com>\r\n"
        f"To: reader@gmail.com\r\n"
        f"{reply}"
        f"Subject: Meter report number {n}\r\n"
        f"Date: {_sent_at(n)}\r\n"
        f"Message-ID: <m{n}@example.com>\r\n"
        f"List-Id: <news.example.com>\r\n"
        f"List-Unsubscribe: <https://example.com/u/{n}>\r\n"
        f"List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
        f"Authentication-Results: mx.google.com; spf={spf}; dkim={dkim}; "
        f"dmarc={dmarc} (p={policy})\r\n"
        f"Content-Type: text/plain\r\n"
        f"\r\n"
        f"Your meter report number {n} is ready.\r\n".encode()
    )


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / ".sendable")


async def _audit_through_store(store: Store, email: ParsedEmail) -> Report:
    """Exactly what scripts/audit.py does: read history, audit, save."""
    history = store.history_for(email)
    report = await audit(email, history=history or None, domain_health=False)
    store.save(email, report)
    return report


def _drift(report: Report) -> dict[str, Finding]:
    return {f.check: f for f in report.findings if f.check.startswith("drift.")}


# ── the chain ──────────────────────────────────────────────────────────────


async def test_the_first_audit_has_nothing_to_compare(store: Store) -> None:
    report = await _audit_through_store(store, _send(1))
    assert all(f.passed for f in _drift(report).values())


async def test_history_accumulates_one_record_per_send(store: Store) -> None:
    for n in range(1, 5):
        await _audit_through_store(store, _send(n))
    assert len(store.history_for_domain("example.com")) == 4


async def test_a_clean_sender_stays_clean_as_history_builds(store: Store) -> None:
    # Four identical-quality sends must not start failing simply because there is
    # now something to compare against.
    for n in range(1, 5):
        report = await _audit_through_store(store, _send(n))
    assert all(f.passed for f in _drift(report).values())


async def test_dmarc_failing_after_a_clean_run_is_caught(store: Store) -> None:
    for n in range(1, 5):
        await _audit_through_store(store, _send(n))
    report = await _audit_through_store(
        store, _send(5, spf="fail", dkim="fail", dmarc="fail", policy="NONE")
    )
    drift = _drift(report)

    regression = drift["drift.d01_dmarc_regression"]
    assert regression.passed is False
    assert regression.severity == "CRITICAL"
    # The message must cite the real history, not a generic warning, or the sender
    # cannot tell whether this is new.
    assert "4-of-4" in regression.message

    flip = drift["drift.d03_auth_flip"]
    assert flip.passed is False
    assert flip.severity == "CRITICAL"

    downgrade = drift["drift.d04_dmarc_policy_downgrade"]
    assert downgrade.passed is False
    assert "p=reject" in downgrade.message
    assert "p=none" in downgrade.message


async def test_a_regression_lowers_the_score(store: Store) -> None:
    for n in range(1, 5):
        clean = await _audit_through_store(store, _send(n))
    regressed = await _audit_through_store(
        store, _send(5, spf="fail", dkim="fail", dmarc="fail", policy="NONE")
    )
    assert regressed.score < clean.score


async def test_a_new_freemail_reply_to_is_caught_once_history_exists(
    store: Store,
) -> None:
    for n in range(1, 6):
        await _audit_through_store(store, _send(n, reply_to="jane@example.com"))
    report = await _audit_through_store(store, _send(6, reply_to="janeokafor2026@gmail.com"))
    divergence = _drift(report)["drift.d11_reply_to_divergence"]
    assert divergence.passed is False
    assert "free personal mailbox" in divergence.message.lower()


async def test_re_auditing_the_same_send_does_not_inflate_the_history(
    store: Store,
) -> None:
    # An agent will re-run the same file. If that added a record, d01 would read
    # "9-of-9 pass" from 3 real sends and overstate how established the sender is.
    for _ in range(3):
        await _audit_through_store(store, _send(1))
    assert len(store.history_for_domain("example.com")) == 1


async def test_the_store_survives_a_reopen(store: Store) -> None:
    # History must come from disk, not from anything held in memory, or it is lost
    # between two agent invocations.
    for n in range(1, 4):
        await _audit_through_store(store, _send(n))
    reopened = Store(store.root)
    assert len(reopened.history_for_domain("example.com")) == 3
