"""Build a ready-to-paste SPF TXT record from the published one + missing
provider includes.

Used by the policy engine's SPF_SENDER_NOT_AUTHORIZED finding so the UI can
hand the user the exact record to publish instead of just "add this provider's
include". Pure string work — no DNS, no I/O.

Correctness rules (a wrong SPF record breaks the user's mail, so these matter):
- Insert new includes BEFORE the `all` mechanism. Anything after `all` is
  ignored by receivers.
- Preserve the existing `all` qualifier (`-all` / `~all` / …). Never change
  enforcement strength.
- Never invent an `all` when the published record has none — that would flip a
  neutral record to an enforcing one. Only a brand-new record gets a default
  `~all`.
- Dedupe: skip includes already present (case-insensitive).
- Respect the 10-lookup SPF limit: every include costs at least one DNS lookup,
  so flag (don't silently emit) a record that would exceed it.
"""

from __future__ import annotations

_ALL_QUALIFIERS = ("-", "~", "?", "+")


def _is_all(token: str) -> bool:
    """True for `all` / `-all` / `~all` / `?all` / `+all`."""
    return token.lstrip("-~?+").lower() == "all"


def _norm(token: str) -> str:
    """Compare mechanisms case-insensitively, ignoring a leading `+`."""
    return token.lstrip("+").lower()


def merge_spf(
    raw: str,
    includes: list[str],
    *,
    all_qualifier: str = "~",
    current_lookups: int = 0,
    lookup_limit: int = 10,
) -> tuple[str, str | None]:
    """Merge `includes` (e.g. ``["include:_spf.google.com"]``) into the published
    SPF record `raw`.

    Returns ``(record, warning)`` where `record` is the full TXT value to
    publish and `warning` is a human note if the result would blow the DNS
    lookup limit (else ``None``).
    """
    # Dedupe requested includes, preserve first-seen order.
    seen: set[str] = set()
    want: list[str] = []
    for inc in includes:
        if not inc:
            continue
        key = _norm(inc)
        if key not in seen:
            seen.add(key)
            want.append(inc)

    raw = (raw or "").strip()
    has_record = raw.lower().startswith("v=spf1")

    if not has_record:
        qual = all_qualifier if all_qualifier in _ALL_QUALIFIERS else "~"
        record = " ".join(["v=spf1", *want, f"{qual}all"])
        added = len(want)
    else:
        body = raw.split()[1:]  # drop the v=spf1 prefix
        existing = {_norm(t) for t in body}
        missing = [inc for inc in want if _norm(inc) not in existing]
        added = len(missing)
        all_idx = next((i for i, t in enumerate(body) if _is_all(t)), None)
        if all_idx is None:
            new_body = body + missing  # no `all` present — append, don't invent one
        else:
            new_body = body[:all_idx] + missing + body[all_idx:]
        record = " ".join(["v=spf1", *new_body])

    projected = current_lookups + added
    warning: str | None = None
    if projected > lookup_limit:
        warning = (
            f"This record needs about {projected} DNS lookups, over the "
            f"{lookup_limit}-lookup SPF limit — flatten or remove unused includes "
            "before publishing, or SPF will PermError and fail for everyone."
        )
    return record, warning
