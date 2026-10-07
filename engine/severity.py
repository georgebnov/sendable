"""Severity enum + score thresholds.

GO / REVIEW / NO_GO verdict comes from `verdict()` below. Composite-score
thresholds (SCORE_GO_MIN, SCORE_REVIEW_MIN) are consumed by scoring.py.
"""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SCORE_GO_MIN = 85
SCORE_REVIEW_MIN = 65


def verdict(score: int, has_critical: bool) -> str:
    if has_critical:
        return "NO_GO"
    if score >= SCORE_GO_MIN:
        return "GO"
    if score >= SCORE_REVIEW_MIN:
        return "REVIEW"
    return "NO_GO"
