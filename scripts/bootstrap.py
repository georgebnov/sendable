"""Seed the `emails` table from Gmail history.

Usage:
    python scripts/bootstrap.py                           # prompts for label
    python scripts/bootstrap.py --label AuditBootstrap
    python scripts/bootstrap.py --query "from:hello@mynewsletter.com newer_than:1y"

One-time Gmail setup (label mode): in Gmail UI, create a label, tag your
historical ESP campaigns with it, then pass --label <name>.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from gmail_ingest.auth import get_service, get_user_email  # noqa: E402
from gmail_ingest.bootstrap import bootstrap_interactive, resolve_query  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Bootstrap emails table from Gmail history.")
    parser.add_argument("--label", help="Gmail label name to import from")
    parser.add_argument("--query", help="Raw Gmail search query (alternative to --label)")
    parser.add_argument("--max", type=int, default=500,
                        help="Abort if query matches more than this many messages (default 500)")
    args = parser.parse_args()

    service = get_service()
    user_email = get_user_email(service)
    print(f"Signed in as: {user_email}")

    label = args.label
    query = args.query
    if not label and not query:
        label = input("Gmail label to import (e.g. AuditBootstrap): ").strip()
        if not label:
            print("No label or query provided. Aborting.", file=sys.stderr)
            return 2

    gmail_query = resolve_query(label, query)
    print(f"Searching: {gmail_query}")

    saved, deduped, filtered = bootstrap_interactive(service, gmail_query, max_count=args.max)
    print(f"\nDone. Saved {saved} threads. Deduped {deduped}. Filtered {filtered} threads with no bulk message.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
