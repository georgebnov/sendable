"""CLI: audit one .eml file.

Usage:
    python scripts/audit_one.py path/to/email.eml [--mode test|production]

Writes JSON to stdout, a copy to output/audit_<ts>.json, and a row to
audits.db. Prints a human-readable summary to stderr.

Mode is auto-detected by default (defaults to TEST when ambiguous).
Pass --mode test or --mode production to override.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Allow `python scripts/audit_one.py ...` without `pip install -e .`.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.parse import parse_eml  # noqa: E402
from audit.runner import audit  # noqa: E402
from memory.derived import extract_all  # noqa: E402
from memory.store import history_for, save_email  # noqa: E402


def _summary(report) -> str:
    lines = [
        "",
        f"Mode:    {report.mode.label}"
        + (f"  (signals: {', '.join(report.mode.signals)})" if report.mode.signals else ""),
    ]
    if report.mode.cleanup_subject_prefix_stripped:
        lines.append(f"         stripped subject prefix: {report.mode.cleanup_subject_prefix_stripped!r}")
    if report.mode.cleanup_headers_stripped:
        lines.append(f"         stripped headers: {', '.join(report.mode.cleanup_headers_stripped)}")
    if report.mode.cleanup_placeholders_substituted:
        n = len(report.mode.cleanup_placeholders_substituted)
        fields = ", ".join(p["field"] for p in report.mode.cleanup_placeholders_substituted)
        lines.append(f"         substituted {n} placeholder(s): {fields}")
    lines += [
        f"Score:   {report.score}/100",
        f"Verdict: {report.verdict}",
        f"From:    {report.from_addr or '(unknown)'}",
        f"Subject: {report.subject or '(none)'}",
        "",
        "Findings:",
    ]
    ordering = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    for f in sorted(report.findings, key=lambda x: (ordering.get(x.severity.value, 9), x.passed)):
        tick = "PASS" if f.passed else "FAIL"
        lines.append(f"  [{f.severity.value:<8}] {tick}  {f.check}: {f.message}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help="path to .eml file")
    parser.add_argument(
        "--mode",
        choices=("test", "production"),
        default=None,
        help="force test or production mode (default: auto-detect)",
    )
    parser.add_argument(
        "--probe-unsub",
        action="store_true",
        help=(
            "actually POST to the List-Unsubscribe URL to verify RFC 8058 "
            "one-click works. WARNING: may trigger a real unsubscribe on "
            "third-party lists. Off by default."
        ),
    )
    args = parser.parse_args()

    path = Path(args.path)
    if not path.exists():
        print(f"File not found: {path}", file=sys.stderr)
        return 1

    raw = path.read_bytes()
    parsed = parse_eml(raw)
    sender_domain = extract_all(parsed).get("from_domain")
    history = history_for(sender_domain, n_limit=100) if sender_domain else []
    report = asyncio.run(audit(
        parsed,
        history=history,
        force_mode=args.mode,
        probe_unsub=args.probe_unsub,
    ))
    row_id, action = save_email(raw, parsed, score=report.score)

    output_dir = ROOT / "output"
    output_dir.mkdir(exist_ok=True)

    ts_utc = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_path = output_dir / f"audit_{ts_utc}.json"
    json_path.write_text(report.model_dump_json(indent=2))
    # Markdown report + humanize disabled — restore humanize() +
    # render_markdown() write here to re-enable.

    print(json.dumps(report.model_dump(), indent=2, default=str))
    print(_summary(report), file=sys.stderr)
    print(f"\nJSON:     {json_path}", file=sys.stderr)
    print(f"audits.db: {action} row={row_id}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
