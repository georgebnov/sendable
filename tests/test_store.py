"""The local report store.

Reports are plain JSON files on disk, one per audit, written once and never
changed. That choice is deliberate. The drift checks ask for at most 30 rows for
one sender, each row 13 flat fields, so the query is a filter and a sort over a
few hundred small files. A database would answer that with a schema, an index,
and a binary file, and buy nothing measurable at this size.

Files also version in git, so someone can commit their audit history, diff it,
and see what changed. Immutable one-file-per-audit means two agents writing at
once cannot corrupt anything.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from engine.parse import ParsedEmail, parse_eml
from engine.report import Report
from engine.runner import audit
from store import SCHEMA_VERSION, Store
from tests.conftest import load


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / ".sendable")


async def _report(name: str = "clean_bulk.eml") -> tuple[ParsedEmail, Report]:
    parsed = parse_eml(load(name))
    return parsed, await audit(parsed, domain_health=False)


def _send(subject: str, *, domain: str = "example.com") -> ParsedEmail:
    """A distinct bulk send from one sender. The subject makes the hash differ."""
    return parse_eml(
        f"From: Jane Okafor <jane@{domain}>\r\n"
        f"To: reader@gmail.com\r\n"
        f"Subject: {subject}\r\n"
        f"Authentication-Results: mx.google.com; spf=pass; dkim=pass; "
        f"dmarc=pass (p=REJECT)\r\n"
        f"Content-Type: text/plain\r\n"
        f"\r\n"
        f"Body for {subject}.\r\n".encode()
    )


# ── writing ────────────────────────────────────────────────────────────────


async def test_save_writes_one_readable_json_file(store: Store) -> None:
    parsed, report = await _report()
    path = store.save(parsed, report)
    assert path.is_file()
    assert path.suffix == ".json"
    data = json.loads(path.read_text())
    assert data["report"]["score"] == report.score
    assert data["facts"]["from_domain"] == "example.com"


async def test_the_file_name_sorts_chronologically_and_names_the_sender(
    store: Store,
) -> None:
    # Sorting by name must equal sorting by time, because that is how history is
    # read back without opening every file.
    parsed, report = await _report()
    path = store.save(parsed, report)
    assert path.name.endswith(".json")
    assert "example.com" in path.name
    assert path.name[:4].isdigit(), "the name must start with the timestamp"


async def test_saving_the_same_email_twice_does_not_duplicate_it(
    store: Store,
) -> None:
    # An agent will re-audit the same file. Two records for one email would
    # double-count that send in every drift comparison.
    parsed, report = await _report()
    first = store.save(parsed, report)
    second = store.save(parsed, report)
    assert first == second
    assert len(list(store.audits_dir.glob("*.json"))) == 1


async def test_two_different_emails_both_get_saved(store: Store) -> None:
    for name in ("clean_bulk.eml", "broken_bulk.eml"):
        parsed = parse_eml(load(name))
        store.save(parsed, await audit(parsed, domain_health=False))
    assert len(list(store.audits_dir.glob("*.json"))) == 2


async def test_the_store_creates_its_own_directories(tmp_path: Path) -> None:
    # A first run must work in an empty project with no setup step.
    store = Store(tmp_path / "nested" / "deeper" / ".sendable")
    parsed, report = await _report()
    assert store.save(parsed, report).is_file()


# ── reading history back ───────────────────────────────────────────────────


async def test_history_is_empty_for_an_unknown_sender(store: Store) -> None:
    assert store.history_for_domain("never-seen.example") == []


async def test_history_round_trips_through_the_fact_row(store: Store) -> None:
    # What the store writes must load back as the same EmailFacts the drift
    # checks compare, or the writer and the reader have drifted apart.
    parsed, report = await _report()
    store.save(parsed, report)
    history = store.history_for_domain("example.com")
    assert len(history) == 1
    row = history[0]
    assert row["from_domain"] == "example.com"
    assert row["dmarc_result"] == "pass"
    assert row["received_at"] is not None


async def test_history_only_returns_the_requested_sender(store: Store) -> None:
    for name in ("clean_bulk.eml", "broken_bulk.eml"):
        parsed = parse_eml(load(name))
        store.save(parsed, await audit(parsed, domain_health=False))
    assert len(store.history_for_domain("example.com")) == 1
    assert len(store.history_for_domain("shady-example.net")) == 1


async def test_history_is_newest_first(store: Store) -> None:
    # d01 and d03 read `history[:10]`, so the order is part of the contract.
    # The sends are saved out of order on purpose.
    for day in (3, 20, 11):
        email = _send(f"report for day {day}")
        store.save(
            email,
            await audit(email, domain_health=False),
            audited_at=f"2026-01-{day:02d}T10:00:00+00:00",
        )
    history = store.history_for_domain("example.com")
    stamps = [r["received_at"] or "" for r in history]
    assert len(stamps) == 3
    assert stamps == sorted(stamps, reverse=True), f"not newest-first: {stamps}"


async def test_history_respects_the_limit(store: Store) -> None:
    for n in range(8):
        email = _send(f"send number {n}")
        store.save(
            email,
            await audit(email, domain_health=False),
            audited_at=f"2026-01-0{n + 1}T10:00:00+00:00",
        )
    assert len(store.history_for_domain("example.com")) == 8
    assert len(store.history_for_domain("example.com", limit=3)) == 3


async def test_the_limit_keeps_the_newest_not_the_first_found(store: Store) -> None:
    # A truncated history that kept the oldest rows would make every drift check
    # compare against a stale baseline.
    for day in range(1, 6):
        email = _send(f"send on day {day}")
        store.save(
            email,
            await audit(email, domain_health=False),
            audited_at=f"2026-01-0{day}T10:00:00+00:00",
        )
    kept = store.history_for_domain("example.com", limit=2)
    assert [r["received_at"] for r in kept] == [
        "2026-01-05T10:00:00+00:00",
        "2026-01-04T10:00:00+00:00",
    ]


async def test_a_corrupt_record_is_skipped_not_fatal(store: Store) -> None:
    # Someone will hand-edit one of these files, or a write will be cut short.
    # One bad file must not make every later audit fail.
    parsed, report = await _report()
    store.save(parsed, report)
    (store.audits_dir / "20260101T000000Z-example.com-deadbeef.json").write_text("{not json")
    assert len(store.history_for_domain("example.com")) == 1


async def test_a_record_missing_its_facts_is_skipped(store: Store) -> None:
    parsed, report = await _report()
    store.save(parsed, report)
    (store.audits_dir / "20260101T000000Z-example.com-cafe1234.json").write_text(
        json.dumps({"schema": 1, "report": {}})
    )
    assert len(store.history_for_domain("example.com")) == 1


# ── the convenience path a caller uses ─────────────────────────────────────


async def test_history_for_an_email_reads_its_own_sender(store: Store) -> None:
    # The caller has a parsed email, not a domain string. Making them extract the
    # registrable domain themselves would duplicate engine logic at every call.
    parsed, report = await _report()
    store.save(parsed, report)
    assert len(store.history_for(parsed)) == 1


async def test_history_for_an_email_with_no_from_address_is_empty(store: Store) -> None:
    parsed = parse_eml(b"Subject: no from header\r\n\r\nbody")
    assert store.history_for(parsed) == []


# ── listing ────────────────────────────────────────────────────────────────


async def test_list_reports_what_was_stored(store: Store) -> None:
    parsed, report = await _report()
    store.save(parsed, report)
    rows = store.list_audits()
    assert len(rows) == 1
    assert rows[0].from_domain == "example.com"
    assert rows[0].score == report.score
    assert rows[0].verdict == report.verdict
    assert rows[0].subject == "Your March water bill dropped 18 percent"


async def test_list_can_filter_by_sender(store: Store) -> None:
    for name in ("clean_bulk.eml", "broken_bulk.eml"):
        parsed = parse_eml(load(name))
        store.save(parsed, await audit(parsed, domain_health=False))
    assert len(store.list_audits()) == 2
    assert len(store.list_audits(from_domain="example.com")) == 1


# ── when the send happened, versus when it was audited ─────────────────────


async def test_received_at_comes_from_the_headers_not_from_the_audit_time(
    store: Store,
) -> None:
    # The drift windows mean "in the last 30 days of sending", not "of auditing".
    # An agent auditing a month-old saved email must not have it counted as today.
    parsed, report = await _report("clean_bulk.eml")
    path = store.save(parsed, report, audited_at="2027-06-01T00:00:00+00:00")
    record = json.loads(path.read_text())
    assert record["audited_at"] == "2027-06-01T00:00:00+00:00"
    # clean_bulk.eml carries Received and Date headers for 2026-09-29.
    assert record["facts"]["received_at"].startswith("2026-09-29")


async def test_a_message_with_no_timestamp_falls_back_to_the_audit_time(
    store: Store,
) -> None:
    # Without this a timestamp-less message would be dropped from every window by
    # rows_within, which skips rows that cannot place themselves on the timeline.
    email = _send("no date header anywhere")
    path = store.save(
        email, await audit(email, domain_health=False), audited_at="2026-05-05T09:00:00+00:00"
    )
    record = json.loads(path.read_text())
    assert record["facts"]["received_at"] == "2026-05-05T09:00:00+00:00"


async def test_the_record_names_its_schema_version(store: Store) -> None:
    # A reader must be able to tell which shape it is looking at before trusting
    # the fields, or an old file becomes unreadable the first time the shape moves.
    parsed, report = await _report()
    record = json.loads(store.save(parsed, report).read_text())
    assert record["schema"] == SCHEMA_VERSION


# ── a record read from disk is validated, not trusted ──────────────────────


def _write_record(store: Store, name: str, facts: dict[str, object]) -> None:
    store.audits_dir.mkdir(parents=True, exist_ok=True)
    (store.audits_dir / name).write_text(
        json.dumps(
            {
                "schema": SCHEMA_VERSION,
                "audited_at": "2026-02-02T10:00:00+00:00",
                "sha256": "0" * 64,
                "facts": facts,
                "report": {"score": 50, "verdict": "REVIEW"},
            }
        )
    )


async def test_a_record_with_no_sender_is_skipped(store: Store) -> None:
    # Without a from_domain there is nothing to compare the row against, so it
    # cannot take part in a drift comparison.
    _write_record(store, "20260202T100000Z-example.com-11111111.json", {"spf_result": "pass"})
    assert store.history_for_domain("example.com") == []


async def test_a_field_of_the_wrong_type_is_read_as_absent(store: Store) -> None:
    # Someone hand-edits one of these files, or a future writer changes a type.
    # A drift check comparing a number against a string would report a change
    # that describes nothing real, so a wrong type is treated as no value.
    _write_record(
        store,
        "20260202T100000Z-example.com-22222222.json",
        {
            "from_domain": "example.com",
            "spf_result": 1,
            "display_name": ["not", "a", "string"],
            "list_unsub_has_https": "yes",
            "num_images": "three",
        },
    )
    rows = store.history_for_domain("example.com")
    assert len(rows) == 1
    assert rows[0]["spf_result"] is None
    assert rows[0]["display_name"] is None
    assert rows[0]["list_unsub_has_https"] is None
    assert rows[0]["num_images"] == 0


async def test_a_boolean_is_not_accepted_where_a_count_belongs(store: Store) -> None:
    # bool is a subclass of int in Python, so `True` would otherwise pass as 1.
    # These fields mean "1 present, 0 absent, None no header", and a bool written
    # by a different writer would be a silent shape change.
    _write_record(
        store,
        "20260202T100000Z-example.com-33333333.json",
        {"from_domain": "example.com", "list_unsub_has_mailto": True},
    )
    rows = store.history_for_domain("example.com")
    assert rows[0]["list_unsub_has_mailto"] is None


async def test_a_record_missing_optional_fields_still_loads(store: Store) -> None:
    # A record written by an older version may not carry every field. It must
    # still contribute what it does have, rather than being dropped.
    _write_record(
        store, "20260202T100000Z-example.com-44444444.json", {"from_domain": "example.com"}
    )
    rows = store.history_for_domain("example.com")
    assert len(rows) == 1
    assert rows[0]["from_domain"] == "example.com"
    assert rows[0]["dmarc_result"] is None
