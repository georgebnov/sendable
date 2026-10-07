"""History helpers shared by drift + voice.

Ported from the PoC memory.store. Pure functions over the per-sender history
list (list of dicts); no DB access. The history rows themselves are sourced
from the production DB by the service layer.
"""

from __future__ import annotations


def cold_start_ok(history: list[dict], min_rows: int = 3) -> bool:
    """True if history is deep enough for drift/voice analysis (row-count gate)."""
    return len(history) >= min_rows
