#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "beautifulsoup4>=4.15",
#   "dnspython>=2.8",
#   "defusedxml>=0.7.1",
#   "confusable-homoglyphs>=3.3.1",
#   "pydantic>=2.13",
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
  2. Runs every check.
  3. Prints the report as JSON on stdout.

It stores nothing and reads nothing but the file you give it.

Progress goes to stderr, so stdout is always parseable JSON.
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


async def _run(raw: bytes, *, offline: bool, probe_unsub: bool, draft: bool) -> Report:
    """Audit the message and return the report. Nothing is written anywhere."""
    return await audit(
        parse_eml(raw),
        domain_health=not offline,
        probe_unsub=probe_unsub,
        draft=draft,
    )


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
    report = asyncio.run(
        _run(
            raw,
            offline=args.offline,
            probe_unsub=args.probe_unsub,
            draft=args.draft,
        )
    )

    # Context on stderr. stdout stays machine-readable.
    if args.draft:
        print(
            "[draft] graded as an unsent draft: the checks that read headers only a "
            "server can add were skipped, not passed.",
            file=sys.stderr,
        )

    json.dump(report.model_dump(mode="json"), sys.stdout, indent=2 if args.pretty else None)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
