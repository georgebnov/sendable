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
# ]
# ///
"""Read DMARC aggregate reports and say what to do next about your domain.

A DMARC aggregate report is an XML file a receiving provider mails you, usually
once a day, listing every source that sent mail claiming to be your domain and
whether each one authenticated. Providers send them to whatever address you put in
the `rua=` tag of your DMARC DNS record.

Usage
  uv run scripts/dmarc.py ingest report.xml.gz [more.zip ...]   store reports
  uv run scripts/dmarc.py status --domain example.com           what to do next
  uv run scripts/dmarc.py senders --domain example.com          who sends for you

Reports may be plain XML, gzipped, or zipped. Providers use all three.

`status` reads every stored report inside the trailing window, works out who sends
for the domain, looks up the live SPF and DMARC records, and reports the single
most useful next step. The chain is deliberate: it will not tell you to tighten
your policy while a real sender of yours is failing alignment, because that would
start rejecting your own mail.

Progress goes to stderr. The report goes to stdout as JSON, so an agent can read
it and a person can pipe it.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.dmarc.dns_records import read_dmarc, read_spf
from engine.dmarc.parser import parse as parse_report
from engine.dmarc.policy_engine import apply_live_spf_fixes, evaluate
from engine.dmarc.window import WINDOW_DAYS, build_window
from store.dmarc import DmarcStore

DEFAULT_STORE = ".sendable"


def _ingest(args: argparse.Namespace) -> int:
    store = DmarcStore(Path(args.store))
    stored = 0
    skipped = 0
    for target in args.files:
        path = Path(target)
        if not path.is_file():
            print(f"[skip] no file at {target}", file=sys.stderr)
            skipped += 1
            continue
        try:
            report = parse_report(path.read_bytes())
        except ValueError as e:
            # A provider occasionally mails a truncated or non-DMARC attachment.
            # One bad file must not stop the rest of the batch.
            print(f"[skip] {path.name}: {e}", file=sys.stderr)
            skipped += 1
            continue
        saved, is_new = store.save(report)
        stored += 1 if is_new else 0
        state = "stored" if is_new else "already stored"
        org = report.org_name or "unknown reporter"
        rows = len(report.records)
        print(f"[{state}] {path.name}: {org}, {rows} record(s) -> {saved.name}", file=sys.stderr)
    print(
        json.dumps({"files": len(args.files), "stored": stored, "skipped": skipped}),
        file=sys.stdout,
    )
    # Nothing stored and something skipped is a failed ingest. Returning 0 let a
    # caller treat it as success, then run `status` and be told to ingest the
    # reports it had just tried to ingest.
    if stored == 0 and skipped:
        print(
            f"error: none of the {len(args.files)} file(s) could be read as a DMARC "
            f"aggregate report. Providers send .xml, .xml.gz, or .zip; check you "
            f"passed the attachment and not the message that carried it.",
            file=sys.stderr,
        )
        return 1
    return 0


def _status(args: argparse.Namespace) -> int:
    store = DmarcStore(Path(args.store))
    domain = args.domain
    reports = store.reports_for(domain, days=args.days)
    if not reports:
        print(
            f"error: no stored DMARC reports for {domain}.\n"
            f"Ingest some first:  uv run scripts/dmarc.py ingest <report.xml.gz>\n"
            f"If you have none, your DMARC record may have no rua= address. "
            f"See the setup guide.",
            file=sys.stderr,
        )
        return 1

    print(
        f"[dmarc] {len(reports)} report(s) for {domain} in the last {args.days} day(s)",
        file=sys.stderr,
    )
    # The baseline must come from BEFORE the window being judged. Built from the
    # same reports, every source is already known and no spoof can be reported.
    window_start = datetime.now(UTC) - timedelta(days=args.days)
    window = build_window(
        reports,
        domain=domain,
        known_providers=store.known_providers(domain, before=window_start),
    )

    # The live DNS read is what makes the advice current. A report describes mail
    # sent days ago, so a fix made today is invisible in it.
    spf = read_spf(domain)
    dmarc = read_dmarc(domain)
    senders = apply_live_spf_fixes(spf, window.senders)
    window.senders = senders

    rua = args.rua or f"mailto:dmarc@{domain}"
    result = evaluate(dmarc, spf, window, rua)

    out = {
        "domain": domain,
        "window_days": args.days,
        "reports_read": len(reports),
        "days_with_data": window.days_with_data,
        "total_messages": window.total_volume,
        "clean_streak_days": window.clean_streak_days,
        "published": {
            "dmarc": {"exists": dmarc.exists, "p": dmarc.p, "sp": dmarc.sp, "pct": dmarc.pct},
            "spf": {
                "exists": spf.exists,
                "record_count": spf.record_count,
                "lookups": spf.lookups,
                "all_qualifier": spf.all_qualifier,
            },
        },
        "next_step": asdict(result.primary),
        "blockers": [asdict(s) for s in result.blockers],
        "spf_findings": [asdict(a) for a in result.spf_findings],
        "senders": [asdict(s) for s in window.senders],
    }
    json.dump(out, sys.stdout, indent=2 if args.pretty else None)
    sys.stdout.write("\n")
    return 0


def _senders(args: argparse.Namespace) -> int:
    store = DmarcStore(Path(args.store))
    reports = store.reports_for(args.domain, days=args.days)
    if not reports:
        print(f"error: no stored DMARC reports for {args.domain}.", file=sys.stderr)
        return 1
    window_start = datetime.now(UTC) - timedelta(days=args.days)
    window = build_window(
        reports,
        domain=args.domain,
        known_providers=store.known_providers(args.domain, before=window_start),
    )
    rows = sorted(window.senders, key=lambda s: s.volume, reverse=True)
    json.dump(
        {
            "domain": args.domain,
            "window_days": args.days,
            "total_messages": window.total_volume,
            "senders": [asdict(s) for s in rows],
        },
        sys.stdout,
        indent=2 if args.pretty else None,
    )
    sys.stdout.write("\n")
    return 0


def main() -> None:
    # The shared flags live on every subcommand rather than before it, so
    # `dmarc.py senders --domain x --pretty` works. Requiring them ahead of the
    # subcommand reads backwards and is the first thing anyone gets wrong.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--store",
        default=DEFAULT_STORE,
        metavar="DIR",
        help=f"Where reports are kept. Default: {DEFAULT_STORE}",
    )
    common.add_argument("--pretty", action="store_true", help="Indent the JSON output.")

    window = argparse.ArgumentParser(add_help=False)
    window.add_argument("--domain", required=True, help="The domain the reports are about.")
    window.add_argument(
        "--days",
        type=int,
        default=WINDOW_DAYS,
        help=f"How far back to read. Default: {WINDOW_DAYS}",
    )

    ap = argparse.ArgumentParser(
        prog="dmarc.py",
        description="Read DMARC aggregate reports and say what to do next about your domain.",
    )
    sub = ap.add_subparsers(dest="command", required=True)

    p_ingest = sub.add_parser(
        "ingest", parents=[common], help="Store one or more aggregate reports."
    )
    p_ingest.add_argument("files", nargs="+", help="Report files: .xml, .xml.gz, or .zip")

    p_status = sub.add_parser(
        "status", parents=[common, window], help="What to do next about this domain."
    )
    p_status.add_argument(
        "--rua",
        default=None,
        help="The address providers should send reports to. Used in any record this suggests.",
    )

    sub.add_parser("senders", parents=[common, window], help="Who sends mail for this domain.")

    args = ap.parse_args()
    if args.command == "ingest":
        raise SystemExit(_ingest(args))
    if args.command == "status":
        raise SystemExit(_status(args))
    raise SystemExit(_senders(args))


if __name__ == "__main__":
    main()
