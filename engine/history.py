"""The per-send fact row that drift compares across sends.

A drift check answers a question no single email can answer: did this sender's
DMARC policy weaken, did their display name change, did the unsubscribe header
disappear. To do that it needs the same flat facts for the current send and for
earlier ones.

`EmailFacts` is that row. `engine.derived.extract_all` builds one from a parsed
email, and a report store reads stored rows back into the same shape. Keeping
one definition means the writer and the reader cannot drift apart.

Every field is optional in value because a real email may not carry the header
it comes from. `received_at` is the one key that can be absent entirely: the
current send has not been stored yet, so it has no recorded receive time.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import NotRequired, TypedDict


class EmailFacts(TypedDict):
    """Flat facts about one send. All values come from headers or body markup."""

    # Sender identity.
    from_domain: str | None  # registrable domain, e.g. "example.com"
    from_local: str | None  # the part before the "@", lowercased
    display_name: str | None  # the name in the From header, lowercased
    reply_to_domain: str | None  # registrable domain of Reply-To

    # Authentication, as the receiving server reported it.
    spf_result: str | None  # "pass", "fail", "softfail", ...
    dkim_result: str | None
    dmarc_result: str | None
    dmarc_policy: str | None  # the p= value the sender published: none/quarantine/reject

    # Unsubscribe affordances. 1 = present, 0 = absent, None = no header at all.
    list_unsub_has_mailto: int | None
    list_unsub_has_https: int | None
    list_unsub_has_oneclick_post: int | None

    # Body shape.
    num_images: int

    # When the receiving server accepted the message, as an ISO-8601 string.
    # Absent on the current send, which has not been stored yet.
    received_at: NotRequired[str | None]


def cold_start_ok(history: list[EmailFacts], min_rows: int = 3) -> bool:
    """True when there are enough earlier sends to compare against.

    Below this, a drift check cannot tell a real change from a first sighting,
    so every check reports "insufficient history" and passes.
    """
    return len(history) >= min_rows


def rows_within(history: list[EmailFacts], days: int) -> list[EmailFacts]:
    """Return the rows whose `received_at` falls inside the last `days`.

    A row is skipped when it has no `received_at`, or when the stored value is
    not a valid ISO-8601 timestamp. Drift measures change over time, so a row
    that cannot place itself on the timeline cannot take part in the comparison.

    A stored timestamp with no timezone is read as UTC.
    """
    cutoff = datetime.now(UTC) - timedelta(days=days)
    out: list[EmailFacts] = []
    for row in history:
        received = row.get("received_at")
        if not received:
            continue
        try:
            at = datetime.fromisoformat(received)
        except ValueError:
            continue
        if at.tzinfo is None:
            at = at.replace(tzinfo=UTC)
        if at >= cutoff:
            out.append(row)
    return out
