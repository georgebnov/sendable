"""Render a value for a sentence a sender reads.

A finding's `message` is product text. Interpolating a list into it prints the
Python repr, so `['commerce-cta', 'financial-promise']` reached users. The list
itself belongs in `details`, where a machine reads it. This renders the same
values for the sentence.
"""

from __future__ import annotations

from collections.abc import Iterable


def listed(values: Iterable[object]) -> str:
    """Join values the way a sentence does: `a`, `a and b`, `a, b and c`.

    An empty input gives an empty string. Every caller builds its message only
    when it has something to report, so an empty list means a bug above here,
    and a hole in the sentence is easier to see than a raised exception during
    an audit.
    """
    items = [str(v) for v in values]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return f"{', '.join(items[:-1])} and {items[-1]}"
