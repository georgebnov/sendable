"""Backfill the derived columns (from_domain, display_name, auth results,
List-Unsubscribe flags, etc.) for existing rows in the `emails` table.

Idempotent — re-running is safe. Rows with non-NULL derived columns are
re-computed each run (cheap; the column values are deterministic from raw).

Usage:
    python3 scripts/backfill_derived.py
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.parse import parse_eml  # noqa: E402
from memory.derived import extract_all  # noqa: E402
from memory.store import DB_PATH, _conn  # noqa: E402

_DERIVED_COLS = (
    "from_domain",
    "from_local",
    "display_name",
    "reply_to_domain",
    "num_images",
    "spf_result",
    "dkim_result",
    "dmarc_result",
    "dmarc_policy",
    "list_unsub_has_mailto",
    "list_unsub_has_https",
    "list_unsub_has_oneclick_post",
)


def main() -> int:
    # _conn() runs migrations, so the columns are guaranteed to exist.
    with _conn() as c:
        c.row_factory = sqlite3.Row
        rows = c.execute("SELECT id, raw FROM emails ORDER BY id").fetchall()

    print(f"Backfilling {len(rows)} row(s) from {DB_PATH}...")
    set_clause = ", ".join(f"{c}=?" for c in _DERIVED_COLS)
    updated = 0
    with _conn() as c:
        for r in rows:
            parsed = parse_eml(r["raw"])
            derived = extract_all(parsed)
            values = tuple(derived[col] for col in _DERIVED_COLS)
            c.execute(
                f"UPDATE emails SET {set_clause} WHERE id=?",
                (*values, r["id"]),
            )
            updated += 1
            if updated % 10 == 0 or updated == len(rows):
                print(f"  {updated}/{len(rows)} processed")

    print(f"Done. Updated {updated} row(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
