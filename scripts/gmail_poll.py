"""Poll Gmail for +audit messages, run audit, write markdown reports.

Auto-detects the signed-in user's email from OAuth, synthesizes the audit
alias (name+audit@domain), uses Gmail's `deliveredto:` + `is:unread` to
find new messages. The poller scans **every folder/tab** so a campaign
cannot hide from the audit:

  - Inbox (Primary, Promotions, Social, Updates, Forums) — these all
    keep the `INBOX` label, so a query without `in:inbox` already
    matches every category tab.
  - Spam, Trash — Gmail's `messages.list` excludes these by default;
    we pass `includeSpamTrash=True` to include them.

Each message's `labelIds` is inspected so the log line and audit input
report exactly where Gmail filed the message. SPAM placement caps the
score (see `audit.runner.SPAM_SCORE_CAP`) so the verdict cannot be GO.
After audit, the message is marked read so the next poll skips it.

One-time setup:
  1. Google Cloud: enable Gmail API, create OAuth 2.0 Desktop credentials,
     save as credentials.json at project root.
  2. First run opens browser for consent; token.json is cached.

Usage:
    python scripts/gmail_poll.py           # polls every 10s
    python scripts/gmail_poll.py 30        # custom interval in seconds
"""

from __future__ import annotations

import asyncio
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.parse import parse_eml  # noqa: E402
from audit.runner import audit  # noqa: E402
from gmail_ingest.auth import (  # noqa: E402
    audit_address_for,
    get_service,
    get_user_email,
)
from gmail_ingest.bootstrap import bootstrap_interactive, resolve_query  # noqa: E402
from gmail_ingest.poller import fetch_by_query, mark_read  # noqa: E402
from memory.derived import extract_all  # noqa: E402
from memory.store import count_emails, history_for, save_email  # noqa: E402

# Gmail label → human-readable folder/tab. Order matters: SPAM/TRASH
# override INBOX-style classification because Gmail can attach both
# (e.g., a message in Trash may still carry CATEGORY_PROMOTIONS).
_LABEL_LOCATION = (
    ("SPAM", "SPAM"),
    ("TRASH", "TRASH"),
    ("CATEGORY_PROMOTIONS", "PROMOTIONS"),
    ("CATEGORY_SOCIAL", "SOCIAL"),
    ("CATEGORY_UPDATES", "UPDATES"),
    ("CATEGORY_FORUMS", "FORUMS"),
    ("CATEGORY_PERSONAL", "PRIMARY"),
    ("INBOX", "INBOX"),
)


def _classify_location(labels: list[str]) -> str:
    label_set = set(labels)
    for needle, name in _LABEL_LOCATION:
        if needle in label_set:
            return name
    return "OTHER"


def _process(
    msg_id: str, raw: bytes, in_spam: bool = False
) -> tuple[int, str, str | None, int, str]:
    parsed = parse_eml(raw)
    sender_domain = extract_all(parsed).get("from_domain")
    history = history_for(sender_domain, n_limit=100) if sender_domain else []
    report = asyncio.run(audit(parsed, history=history, in_spam=in_spam))
    row_id, action = save_email(raw, parsed, score=report.score)
    # Markdown report + humanize disabled — restore humanize() +
    # render_markdown() write here to re-enable.
    return report.score, report.verdict, report.subject, row_id, action


def main() -> int:
    interval = int(sys.argv[1]) if len(sys.argv) >= 2 else 10

    service = get_service()
    user_email = get_user_email(service)
    audit_addr = audit_address_for(user_email)

    print(f"Signed in as: {user_email}")
    print(f"Audit address: {audit_addr}")

    if count_emails() == 0:
        print("\nNo emails in memory yet — drift detection needs history.")
        resp = input("Bootstrap from Gmail now? [Y/n]: ").strip().lower()
        if resp in ("", "y", "yes"):
            label = input("Gmail label to import (e.g. AuditBootstrap): ").strip()
            if label:
                saved, deduped, filtered = bootstrap_interactive(service, resolve_query(label, None))
                print(f"Bootstrap done. Saved {saved} threads, deduped {deduped}, filtered {filtered} with no bulk.")

    # No `in:inbox` filter — that would exclude category tabs that are
    # technically still in inbox but route through Promotions/Social/etc.
    # `fetch_by_query` adds `includeSpamTrash=True` so Spam and Trash also
    # surface. Net: we see every folder.
    query = f"deliveredto:{audit_addr} is:unread"
    print(
        f"\nPolling every {interval}s — covers Primary, Promotions, Social, "
        f"Updates, Forums, Spam, Trash. Ctrl-C to stop."
    )
    try:
        while True:
            matches = fetch_by_query(service, query)
            for msg_id, raw, labels in matches:
                location = _classify_location(labels)
                in_spam = location == "SPAM"
                score, verdict, subject, row_id, action = _process(
                    msg_id, raw, in_spam=in_spam
                )
                mark_read(service, msg_id)
                stamp = datetime.now().isoformat(timespec="seconds")
                subj = (subject or "(no subject)")[:40]
                print(
                    f"[{stamp}] {location} {action.upper()} row={row_id} "
                    f"{verdict} score={score} {subj!r}"
                )
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopped.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
