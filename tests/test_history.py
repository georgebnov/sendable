"""The shared history row and the date window every drift check sits on.

`EmailFacts` is the one definition of a per-send fact row. `engine.derived`
writes it from a parsed email and a report store reads stored rows back into it,
so a defect here reaches all 6 drift checks at once.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from engine.history import EmailFacts, cold_start_ok, rows_within


def _row(**over: object) -> EmailFacts:
    """A complete row. Tests override only the field under test."""
    base: EmailFacts = {
        "from_domain": "example.com",
        "from_local": "jane",
        "display_name": "jane agent",
        "reply_to_domain": None,
        "spf_result": "pass",
        "dkim_result": "pass",
        "dmarc_result": "pass",
        "dmarc_policy": "none",
        "list_unsub_has_mailto": 1,
        "list_unsub_has_https": 1,
        "list_unsub_has_oneclick_post": 1,
        "num_images": 0,
        "received_at": datetime.now(UTC).isoformat(),
    }
    base.update(over)  # type: ignore[typeddict-item]
    return base


def _days_ago(n: int) -> str:
    return (datetime.now(UTC) - timedelta(days=n)).isoformat()


# ── cold_start_ok ──────────────────────────────────────────────────────────


def test_cold_start_needs_three_rows_by_default() -> None:
    assert cold_start_ok([]) is False
    assert cold_start_ok([_row(), _row()]) is False
    assert cold_start_ok([_row(), _row(), _row()]) is True


def test_cold_start_threshold_is_caller_set() -> None:
    # d10 asks for 8 rows, because a rotation needs a longer baseline.
    rows = [_row() for _ in range(7)]
    assert cold_start_ok(rows, min_rows=8) is False
    assert cold_start_ok([*rows, _row()], min_rows=8) is True


# ── rows_within ────────────────────────────────────────────────────────────


def test_keeps_rows_inside_the_window_and_drops_older_ones() -> None:
    rows = [
        _row(received_at=_days_ago(1)),
        _row(received_at=_days_ago(29)),
        _row(received_at=_days_ago(31)),
        _row(received_at=_days_ago(400)),
    ]
    kept = rows_within(rows, days=30)
    assert len(kept) == 2


def test_row_without_a_timestamp_is_dropped_not_raised() -> None:
    # A row with no received_at cannot place itself on the timeline. Before the
    # window logic was extracted, this reached datetime.fromisoformat(None) and
    # raised a TypeError that a broad `except Exception` then swallowed.
    rows = [_row(received_at=None), _row(received_at=_days_ago(1))]
    kept = rows_within(rows, days=30)
    assert len(kept) == 1


def test_row_with_an_unparsable_timestamp_is_dropped() -> None:
    rows = [_row(received_at="last Tuesday"), _row(received_at=_days_ago(2))]
    kept = rows_within(rows, days=30)
    assert len(kept) == 1


def test_missing_received_at_key_entirely_is_dropped() -> None:
    # received_at is NotRequired: engine.derived.extract_all builds the current
    # send, which has no stored receive time yet.
    bare = _row()
    del bare["received_at"]
    kept = rows_within([bare, _row(received_at=_days_ago(1))], days=30)
    assert len(kept) == 1


def test_naive_timestamp_is_read_as_utc() -> None:
    naive = (datetime.now(UTC) - timedelta(days=1)).replace(tzinfo=None).isoformat()
    assert "+" not in naive
    assert len(rows_within([_row(received_at=naive)], days=30)) == 1


def test_window_is_empty_when_every_row_is_too_old() -> None:
    rows = [_row(received_at=_days_ago(n)) for n in (100, 200, 300)]
    assert rows_within(rows, days=30) == []
