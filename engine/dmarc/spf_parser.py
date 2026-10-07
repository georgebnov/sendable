"""Parse a published SPF record into the SpfRecord shape policy_engine wants.

Two metrics matter:

  - lookups: how many DNS lookups the record costs. RFC 7208 caps at 10;
    over that = PermError, SPF fails for everyone. We count the lookup
    mechanisms (include, a, mx, ptr, exists, redirect). 'a' / 'mx' count
    once each; 'include' costs one plus whatever its target costs (we
    treat each include as 1 for the surface-level audit — recursive
    resolution would be a separate pass, not needed for the v1 cliff
    check).

  - all_qualifier: the final 'all' rule's qualifier.
      '-' hardfail (strict)
      '~' softfail (rollout)
      '?' neutral (weak)
      '+' allow-all (dangerous)
      ''  missing (also weak)
"""

from __future__ import annotations

import re

from engine.dmarc.policy_engine import SpfRecord

_LOOKUP_MECHANISMS = ("include", "a", "mx", "ptr", "exists", "redirect")

# Match the 'all' rule with optional qualifier in front, anchored to a word.
_ALL_RE = re.compile(r"(?:^|\s)([\-~?+])?all\b", re.IGNORECASE)


def parse(records: list[str]) -> SpfRecord:
    """Given the raw TXT strings returned for a domain's SPF lookup, return
    an SpfRecord summary.

    The caller is responsible for filtering to v=spf1 records before passing in.
    """
    if not records:
        return SpfRecord(exists=False)

    record_count = len(records)
    raw = records[0]
    # Normalise: SPF can be split across quoted strings in TXT; we join with
    # space and lowercase the mechanism keywords for parsing.
    body = " ".join(records[0].split())

    # all qualifier
    m = _ALL_RE.search(body)
    if m:
        qualifier = m.group(1) or "+"  # bare 'all' = +all by RFC
    else:
        qualifier = ""

    # lookup count — count distinct mechanism occurrences
    lookups = 0
    for token in body.split():
        # tokens like "include:_spf.google.com" or "a" or "+include:..."
        bare = token.lstrip("+-~?").lower()
        head = bare.split(":", 1)[0].split("=", 1)[0]
        if head in _LOOKUP_MECHANISMS:
            lookups += 1

    return SpfRecord(
        exists=True,
        record_count=record_count,
        lookups=lookups,
        all_qualifier=qualifier,
        raw=raw,
    )
