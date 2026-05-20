"""CLI stub: full pipeline (Step 4).

generate copy -> human edits in ESP -> test-send -> audit (via CloudMailin
inbound or local .eml) -> human re-edits -> loop -> ship.

Not yet implemented — depends on Step 3 (copy gen) and the CloudMailin
webhook (Phase 2 infra). See BACKLOG.md.
"""

import sys


def main() -> int:
    print("Full pipeline not yet implemented (Step 4 of the PoC plan).", file=sys.stderr)
    print("See PIPELINE.md and BACKLOG.md.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
