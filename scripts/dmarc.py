#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
# ]
# ///
"""Read DMARC aggregate reports and say what to do next about your domain.

A DMARC aggregate report is an XML file a receiving provider mails you, usually
once a day, listing every source that sent mail claiming to be your domain and
whether each one authenticated. Providers send them to whatever address you put
in the `rua=` tag of your DMARC DNS record.

Usage
  uv run scripts/dmarc.py report.xml.gz [more.zip ...]
  uv run scripts/dmarc.py ~/Downloads/*.xml.gz --domain example.com --pretty

Reports may be plain XML, gzipped, or zipped. Providers use all three, and a
batch may mix them.

This stores nothing. You pass the reports you have, it reads them, and it prints
the answer. Pass more reports to see further back.

It works out who sends for the domain, reads the live SPF and DMARC records, and
reports the single most useful next step. The chain is deliberate: it will not
tell you to tighten your policy while a real sender of yours is failing
alignment, because that would start rejecting your own mail.

Every report you pass is judged, whatever its date. A sender that appears only
in the newest reporting period, and in none before it, is a new sender,
which is what separates "a spoof just started" from "your provider added an IP".
Pass a wider spread of dates and that detection sharpens. Pass a single day and
it is skipped rather than guessed.

Progress goes to stderr. The report goes to stdout as JSON, so an agent can read
it and a person can pipe it.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.dmarc.dns_records import read_dmarc, read_spf
from engine.dmarc.parser import DmarcReport
from engine.dmarc.parser import parse as parse_report
from engine.dmarc.policy_engine import apply_live_spf_fixes, evaluate
from engine.dmarc.window import (
    build_window,
    for_domain,
    known_providers_before_latest,
    pick_domain,
)


def _read(paths: list[str]) -> tuple[list[DmarcReport], int]:
    """Parse every file. A bad one is skipped, not fatal.

    A provider occasionally mails a truncated or non-DMARC attachment, and one
    bad file must not stop the rest of the batch.
    """
    reports: list[DmarcReport] = []
    skipped = 0
    for target in paths:
        path = Path(target)
        if not path.is_file():
            print(f"[skip] no file at {target}", file=sys.stderr)
            skipped += 1
            continue
        try:
            report = parse_report(path.read_bytes())
        except ValueError as e:
            print(f"[skip] {path.name}: {e}", file=sys.stderr)
            skipped += 1
            continue
        reports.append(report)
        org = report.org_name or "unknown reporter"
        print(f"[read] {path.name}: {org}, {len(report.records)} record(s)", file=sys.stderr)
    return reports, skipped


def main() -> None:
    ap = argparse.ArgumentParser(
        prog="dmarc.py",
        description="Read DMARC aggregate reports and say what to do next about your domain.",
    )
    ap.add_argument("files", nargs="+", help="Report files: .xml, .xml.gz, or .zip")
    ap.add_argument(
        "--domain",
        default=None,
        help="The domain to judge. Only needed when the batch covers more than one.",
    )
    ap.add_argument(
        "--rua",
        default=None,
        help="The address providers should send reports to. Used in any record this suggests.",
    )
    ap.add_argument("--pretty", action="store_true", help="Indent the JSON output.")
    args = ap.parse_args()

    reports, skipped = _read(args.files)
    if not reports:
        print(
            f"error: none of the {len(args.files)} file(s) could be read as a DMARC "
            f"aggregate report. Providers send .xml, .xml.gz, or .zip; check you "
            f"passed the attachment and not the message that carried it.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    domain = args.domain or pick_domain(reports)
    if domain is None:
        found = sorted({r.policy.domain for r in reports if r.policy and r.policy.domain})
        print(
            "error: these reports cover more than one domain, so say which to judge:\n"
            f"  --domain {found[0] if found else 'example.com'}\n"
            f"Found: {', '.join(found) if found else 'no policy domain in any report'}",
            file=sys.stderr,
        )
        raise SystemExit(1)

    mine = for_domain(reports, domain)
    if not mine:
        found = sorted({r.policy.domain for r in reports if r.policy and r.policy.domain})
        print(
            f"error: none of the {len(reports)} report(s) cover {domain}.\n"
            f"These do: {', '.join(found) if found else 'no policy domain in any report'}.\n"
            f"Drop --domain to judge whichever domain the reports are about.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    # Every report the user passed is judged. Nothing collects reports for them,
    # so the files on the command line are the whole dataset, and discarding any
    # of them by date would throw away the only data there is.
    known_providers = known_providers_before_latest(mine)

    print(
        f"[dmarc] {len(mine)} report(s) for {domain}"
        + (
            ", comparing the newest period against what sent before it"
            if known_providers is not None
            else " covering one period, so new-sender detection is off "
            "(add a report from an earlier day to turn it on)"
        ),
        file=sys.stderr,
    )

    window = build_window(mine, domain=domain, known_providers=known_providers)

    # The live DNS read is what makes the advice current. A report describes mail
    # sent days ago, so a fix made today is invisible in it.
    spf = read_spf(domain)
    dmarc = read_dmarc(domain)
    window.senders = apply_live_spf_fixes(spf, window.senders)

    rua = args.rua or f"mailto:dmarc@{domain}"
    result = evaluate(dmarc, spf, window, rua)

    out = {
        "domain": domain,
        "reports_read": len(mine),
        "files_skipped": skipped,
        "days_with_data": window.days_with_data,
        "total_messages": window.total_volume,
        "clean_streak_days": window.clean_streak_days,
        "new_sender_detection": known_providers is not None,
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
        "senders": [
            asdict(s) for s in sorted(window.senders, key=lambda s: s.volume, reverse=True)
        ],
    }
    json.dump(out, sys.stdout, indent=2 if args.pretty else None)
    sys.stdout.write("\n")
    raise SystemExit(0)


if __name__ == "__main__":
    main()
