"""Tracking what the store holds: history, trend, and the senders seen.

"Track everything locally" is the reason reports are stored at all. A single audit
answers "is this email good". The stored set answers the questions a sender
actually acts on: is my score moving, which problems keep coming back, and which
of my senders is the weak one.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from engine.parse import ParsedEmail, parse_eml
from engine.runner import audit
from store import Store
from store.trends import check_frequency, domain_summaries, score_history
from tests.conftest import load


def _send(n: int, *, domain: str = "example.com", dmarc: str = "pass") -> ParsedEmail:
    return parse_eml(
        f"From: Jane Okafor <jane@{domain}>\r\n"
        f"To: reader@gmail.com\r\n"
        f"Subject: Report number {n}\r\n"
        f"Date: Tue, {n + 10:02d} Sep 2026 09:14:02 -0700\r\n"
        f"Message-ID: <m{n}@{domain}>\r\n"
        f"Authentication-Results: mx.google.com; spf=pass; dkim=pass; "
        f"dmarc={dmarc} (p=REJECT)\r\n"
        f"Content-Type: text/plain\r\n"
        f"\r\n"
        f"Body number {n}.\r\n".encode()
    )


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / ".sendable")


async def _fill(store: Store, count: int, **kw: object) -> None:
    for n in range(1, count + 1):
        email = _send(n, **kw)  # type: ignore[arg-type]
        store.save(email, await audit(email, domain_health=False))


# ── score history ──────────────────────────────────────────────────────────


async def test_score_history_is_empty_for_an_empty_store(store: Store) -> None:
    assert score_history(store) == []


async def test_score_history_returns_one_point_per_audit(store: Store) -> None:
    await _fill(store, 4)
    points = score_history(store)
    assert len(points) == 4
    assert all(0 <= p.score <= 100 for p in points)


async def test_score_history_is_oldest_first(store: Store) -> None:
    # A trend reads left to right. Newest-first would invert every direction.
    await _fill(store, 4)
    stamps = [p.at for p in score_history(store)]
    assert stamps == sorted(stamps)


async def test_score_history_can_be_narrowed_to_one_sender(store: Store) -> None:
    await _fill(store, 2, domain="example.com")
    await _fill(store, 3, domain="other.test")
    assert len(score_history(store, from_domain="other.test")) == 3


# ── which problems keep coming back ────────────────────────────────────────


async def test_check_frequency_counts_only_failures(store: Store) -> None:
    await _fill(store, 3)
    counts = check_frequency(store)
    assert counts, "a store with failing audits must report something"
    assert all(n > 0 for n in counts.values())


async def test_check_frequency_is_ordered_by_how_often_it_fails(store: Store) -> None:
    # The point is to name the recurring problem, so the worst must be first.
    await _fill(store, 4)
    values = list(check_frequency(store).values())
    assert values == sorted(values, reverse=True)


async def test_a_check_that_never_fails_is_absent(store: Store) -> None:
    await _fill(store, 3)
    counts = check_frequency(store)
    # These pass on every fixture above, so they must not appear as problems.
    assert "auth.spf" not in counts
    assert "auth.dkim" not in counts


# ── per-sender summary ─────────────────────────────────────────────────────


async def test_domain_summaries_reports_each_sender_once(store: Store) -> None:
    await _fill(store, 2, domain="example.com")
    await _fill(store, 3, domain="other.test")
    summaries = domain_summaries(store)
    assert {s.from_domain for s in summaries} == {"example.com", "other.test"}
    by_domain = {s.from_domain: s for s in summaries}
    assert by_domain["other.test"].audits == 3


async def test_domain_summaries_reports_the_latest_and_the_average(store: Store) -> None:
    await _fill(store, 3)
    summary = domain_summaries(store)[0]
    assert summary.audits == 3
    assert 0 <= summary.average_score <= 100
    assert 0 <= summary.latest_score <= 100
    assert summary.worst_verdict in {"GO", "REVIEW", "NO_GO"}


async def test_domain_summaries_keeps_the_worst_verdict_not_the_latest(
    store: Store,
) -> None:
    # A sender whose last send was fine but who failed earlier has a problem worth
    # surfacing. Reporting only the latest would hide it.
    await _fill(store, 2, dmarc="fail")
    await _fill(store, 1, dmarc="pass")
    summary = domain_summaries(store)[0]
    assert summary.worst_verdict == "NO_GO"


async def test_domain_summaries_is_ordered_worst_first(store: Store) -> None:
    # The two fixtures separate sharply: clean_bulk scores 98 GO and broken_bulk
    # scores 26 NO_GO. The minimal inline sends above all score the same, so they
    # cannot show an ordering.
    for name in ("clean_bulk.eml", "broken_bulk.eml"):
        email = parse_eml(load(name))
        store.save(email, await audit(email, domain_health=False))
    summaries = domain_summaries(store)
    assert summaries[0].worst_verdict == "NO_GO", "the sender needing attention comes first"
    assert summaries[-1].worst_verdict == "GO"


async def test_two_senders_that_score_the_same_sort_deterministically(
    store: Store,
) -> None:
    # Without a tiebreak the order came from whichever file the filesystem listed
    # first, so the same store could print two different orders.
    await _fill(store, 1, domain="bbb.test")
    await _fill(store, 1, domain="aaa.test")
    first = [s.from_domain for s in domain_summaries(store)]
    second = [s.from_domain for s in domain_summaries(store)]
    assert first == second == ["aaa.test", "bbb.test"]


async def test_domain_summaries_is_empty_for_an_empty_store(store: Store) -> None:
    assert domain_summaries(store) == []
