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
"""Read what the store already holds. Nothing here audits or writes.

One audit answers "is this email good". The stored set answers the questions a
sender acts on.

Usage
  uv run scripts/reports.py list                      every audit, newest first
  uv run scripts/reports.py trend                     how the score is moving
  uv run scripts/reports.py problems                  what keeps failing
  uv run scripts/reports.py senders                   one row per sending domain
  uv run scripts/reports.py show <sha-or-path>        one full report

Every subcommand takes `--json` for machine output. Without it the output is a
plain table meant for a person. `--domain` narrows the first four to one sender.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from store import Store
from store.trends import check_frequency, domain_summaries, score_history

DEFAULT_STORE = ".sendable"


def _day(stamp: str) -> str:
    """The date part of an ISO timestamp, for a table column."""
    return stamp[:10] if len(stamp) >= 10 else stamp


def _emit(data: object) -> None:
    """Print a machine-readable payload. Callers render their own table."""
    json.dump(data, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


def _cmd_list(store: Store, args: argparse.Namespace) -> int:
    rows = store.list_audits(from_domain=args.domain)
    if not rows:
        print("No audits stored yet. Run scripts/audit.py on an email first.", file=sys.stderr)
        return 1
    if args.json:
        _emit([asdict(r) | {"path": str(r.path)} for r in rows])
        return 0
    print(f"{'DATE':<11} {'SCORE':>5} {'VERDICT':<8} {'SENDER':<24} SUBJECT")
    for r in rows:
        print(
            f"{_day(r.audited_at):<11} {r.score:>5} {r.verdict:<8} "
            f"{(r.from_domain or '-'):<24} {(r.subject or '')[:46]}"
        )
    return 0


def _cmd_trend(store: Store, args: argparse.Namespace) -> int:
    points = score_history(store, from_domain=args.domain)
    if not points:
        print("No audits stored yet.", file=sys.stderr)
        return 1
    if args.json:
        _emit([asdict(p) for p in points])
        return 0
    print(f"{'DATE':<11} {'SCORE':>5}  {'':<22} VERDICT")
    for p in points:
        # A 20-cell bar: each cell is 5 points, so the shape is readable at a glance.
        bar = "#" * max(1, round(p.score / 5))
        print(f"{_day(p.at):<11} {p.score:>5}  {bar:<22} {p.verdict}")
    first, last = points[0].score, points[-1].score
    move = last - first
    direction = "up" if move > 0 else ("down" if move < 0 else "flat")
    print(f"\n{len(points)} audit(s). First {first}, latest {last}: {direction} by {abs(move)}.")
    return 0


def _cmd_problems(store: Store, args: argparse.Namespace) -> int:
    counts = check_frequency(store, from_domain=args.domain)
    if not counts:
        print("Nothing has failed in the stored audits.", file=sys.stderr)
        return 1
    total = len(score_history(store, from_domain=args.domain))
    if args.json:
        _emit({"audits": total, "failures_by_check": counts})
        return 0
    print(f"Across {total} audit(s), worst first:\n")
    print(f"{'FAILED IN':>9}  CHECK")
    for name, n in counts.items():
        print(f"{n:>5}/{total:<3}  {name}")
    print("\nThe first line is the thing worth fixing: it is the one that keeps happening.")
    return 0


def _cmd_senders(store: Store, args: argparse.Namespace) -> int:
    rows = domain_summaries(store)
    if not rows:
        print("No audits stored yet.", file=sys.stderr)
        return 1
    if args.json:
        _emit([asdict(r) for r in rows])
        return 0
    print(f"{'SENDER':<28} {'AUDITS':>6} {'LATEST':>6} {'AVG':>5} {'WORST':<8} LAST SEEN")
    for r in rows:
        print(
            f"{r.from_domain:<28} {r.audits:>6} {r.latest_score:>6} "
            f"{r.average_score:>5} {r.worst_verdict:<8} {_day(r.latest_at)}"
        )
    print("\nThe first row is the sender to look at.")
    return 0


def _cmd_show(store: Store, args: argparse.Namespace) -> int:
    """Print one full report, found by file path or by the start of its hash."""
    target = args.target
    path = Path(target)
    if not path.is_file():
        matches = [r for r in store.list_audits() if r.sha256.startswith(target.lower())]
        if not matches:
            print(
                f"error: no stored audit matching {target!r}.\n"
                f"Pass a file path, or the start of a sha256 as shown by "
                f"`reports.py list --json`.",
                file=sys.stderr,
            )
            return 1
        if len(matches) > 1:
            print(
                f"error: {target!r} matches {len(matches)} audits. Use more characters.",
                file=sys.stderr,
            )
            return 1
        path = matches[0].path
    sys.stdout.write(path.read_text(encoding="utf-8"))
    return 0


def main() -> None:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--store",
        default=DEFAULT_STORE,
        metavar="DIR",
        help=f"Where reports are kept. Default: {DEFAULT_STORE}",
    )
    common.add_argument("--json", action="store_true", help="Machine-readable output.")

    scoped = argparse.ArgumentParser(add_help=False)
    scoped.add_argument("--domain", default=None, help="Only this sending domain.")

    ap = argparse.ArgumentParser(
        prog="reports.py", description="Read what the local audit store already holds."
    )
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("list", parents=[common, scoped], help="Every audit, newest first.")
    sub.add_parser("trend", parents=[common, scoped], help="How the score is moving.")
    sub.add_parser("problems", parents=[common, scoped], help="What keeps failing.")
    sub.add_parser("senders", parents=[common], help="One row per sending domain.")
    p_show = sub.add_parser("show", parents=[common], help="One full report.")
    p_show.add_argument("target", help="A file path, or the start of an audit's sha256.")

    args = ap.parse_args()
    store = Store(args.store)
    handlers = {
        "list": _cmd_list,
        "trend": _cmd_trend,
        "problems": _cmd_problems,
        "senders": _cmd_senders,
        "show": _cmd_show,
    }
    raise SystemExit(handlers[args.command](store, args))


if __name__ == "__main__":
    main()
