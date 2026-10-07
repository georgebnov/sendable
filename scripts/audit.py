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
#   "openai>=2.41",
# ]
# ///
"""Audit one email file and print the report as JSON.

Usage:
  uv run scripts/audit.py <file.eml>
  cat mail.eml | uv run scripts/audit.py -

Flags:
  --offline   Skip every check that needs the network (DNS, RBL, SMTP probe).
              Use this to audit copy and structure with no outbound traffic.
  --pretty    Indent the JSON for a human reader.

The script needs no install step. `uv` reads the dependency list above,
resolves it once, and caches it. Set OPENAI_API_KEY to enable the checks
that ask a model a question. Without the key those checks report INFO and
pass, so the audit still runs.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.parse import parse_eml  # noqa: E402
from engine.runner import audit  # noqa: E402


def _read_source(target: str) -> bytes:
    if target == "-":
        return sys.stdin.buffer.read()
    path = Path(target)
    if not path.is_file():
        sys.exit(
            f"error: no file at {target}\n"
            f"Pass the path to a saved email (.eml), or '-' to read it from stdin."
        )
    return path.read_bytes()


async def _run(raw: bytes, *, offline: bool) -> dict:
    report = await audit(parse_eml(raw), domain_health=not offline)
    return report.model_dump(mode="json")


def main() -> None:
    ap = argparse.ArgumentParser(
        prog="audit.py",
        description="Audit one email file for deliverability and copy problems.",
    )
    ap.add_argument("target", help="Path to an .eml file, or '-' for stdin.")
    ap.add_argument(
        "--offline",
        action="store_true",
        help="Skip the checks that need the network (DNS, RBL, SMTP probe).",
    )
    ap.add_argument("--pretty", action="store_true", help="Indent the JSON output.")
    args = ap.parse_args()

    raw = _read_source(args.target)
    report = asyncio.run(_run(raw, offline=args.offline))
    json.dump(report, sys.stdout, indent=2 if args.pretty else None)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
