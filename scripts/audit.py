#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "beautifulsoup4>=4.15",
#   "lxml>=6.1",
#   "dnspython>=2.8",
#   "defusedxml>=0.7.1",
#   "confusable-homoglyphs>=3.3.1",
#   "publicsuffixlist>=1.0.2",
#   "pydantic>=2.13",
#   "cryptography>=46.0",
#   "pyasn1>=0.6",
#   "openai>=2.41",
# ]
# ///
"""Audit one email for deliverability, inbox placement, and copy problems.

Usage
  uv run scripts/audit.py mail.eml
  cat mail.eml | uv run scripts/audit.py -

The script needs no install step. `uv` reads the dependency list above, resolves
it once, and caches it.

What it does, in order:
  1. Parses the email.
  2. Reads this sender's earlier audits from the local store.
  3. Runs the checks, including the 6 drift checks that compare this send against
     those earlier ones.
  4. Stores the report, so the next audit of this sender has more to compare.
  5. Prints the report as JSON on stdout.

Progress and cost go to stderr, so stdout is always parseable JSON.

Set OPENAI_API_KEY to enable the checks that ask a model a question. Without it
those checks report INFO and pass, and the rest of the audit is unaffected.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.parse import parse_eml
from engine.report import Report
from engine.runner import audit
from store import Store

DEFAULT_STORE = ".sendable"


def _read_source(target: str) -> bytes:
    if target == "-":
        data = sys.stdin.buffer.read()
        if not data:
            sys.exit("error: nothing arrived on stdin. Pipe an email, or pass a file path.")
        return data
    path = Path(target)
    if not path.is_file():
        sys.exit(
            f"error: no file at {target}\n"
            f"Pass the path to a saved email (.eml), or '-' to read it from stdin."
        )
    return path.read_bytes()


async def _run(
    raw: bytes,
    *,
    offline: bool,
    store: Store | None,
    probe_unsub: bool,
    draft: bool,
) -> tuple[Report, int, Path | None]:
    """Audit the message. Returns the report, the history depth, and where it was stored."""
    email = parse_eml(raw)
    history = store.history_for(email) if store is not None else []
    report = await audit(
        email,
        history=history or None,
        domain_health=not offline,
        probe_unsub=probe_unsub,
        draft=draft,
    )
    saved = store.save(email, report, raw=raw) if store is not None else None
    return report, len(history), saved


def main() -> None:
    ap = argparse.ArgumentParser(
        prog="audit.py",
        description="Audit one email for deliverability, inbox placement, and copy problems.",
    )
    ap.add_argument("target", help="Path to an .eml file, or '-' to read it from stdin.")
    ap.add_argument(
        "--offline",
        action="store_true",
        help=(
            "Skip every check that needs the network: DNS records, the blocklist "
            "fan-out, and the SMTP probe. Copy and structure checks still run."
        ),
    )
    ap.add_argument(
        "--store",
        default=DEFAULT_STORE,
        metavar="DIR",
        help=f"Where reports are kept. Default: {DEFAULT_STORE}",
    )
    ap.add_argument(
        "--no-store",
        action="store_true",
        help=(
            "Audit without reading or writing the store. The drift checks then "
            "have nothing to compare against."
        ),
    )
    ap.add_argument(
        "--draft",
        action="store_true",
        help=(
            "Grade a message that has not been sent yet. Skips the checks that "
            "read headers only a server can add: SPF, DKIM, and DMARC results and "
            "alignment, transport encryption, Date, and Message-ID. Without this, "
            "a good draft scores NO_GO because none of those exist."
        ),
    )
    ap.add_argument(
        "--probe-unsub",
        action="store_true",
        help=(
            "Fetch the unsubscribe URL to check it answers. Off by default, because "
            "it makes a request to a URL taken from the email under audit."
        ),
    )
    ap.add_argument("--pretty", action="store_true", help="Indent the JSON output.")
    args = ap.parse_args()

    if args.offline and args.probe_unsub:
        sys.exit(
            "error: --offline and --probe-unsub contradict each other.\n"
            "--offline means no outbound traffic at all. --probe-unsub fetches the "
            "unsubscribe URL from the email under audit.\n"
            "Drop one of them."
        )

    raw = _read_source(args.target)
    # A draft is not a send. Storing it would add a row with no authentication
    # results to the history that every drift check reads, making a clean
    # sender look like it had started failing.
    store = None if (args.no_store or args.draft) else Store(args.store)
    report, depth, saved = asyncio.run(
        _run(
            raw,
            offline=args.offline,
            store=store,
            probe_unsub=args.probe_unsub,
            draft=args.draft,
        )
    )

    # Context on stderr. stdout stays machine-readable.
    if args.draft:
        print(
            "[draft] graded as an unsent draft. Not stored, because a draft has "
            "no authentication results and would skew this sender's history.",
            file=sys.stderr,
        )
    if store is not None:
        if depth:
            print(
                f"[store] compared against {depth} earlier send(s) from this sender",
                file=sys.stderr,
            )
        else:
            print(
                "[store] no earlier sends from this sender, so the 6 drift checks "
                "had nothing to compare. They start reporting from the 3rd audit.",
                file=sys.stderr,
            )
        if saved is not None:
            print(f"[store] saved {saved}", file=sys.stderr)

    json.dump(report.model_dump(mode="json"), sys.stdout, indent=2 if args.pretty else None)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
