"""Where a published record sits on the ladder, when it is not on a rung.

The ladder has fixed rungs: none, quarantine at 25, 50 and 100, then reject at
25, 50 and 100. A real record can hold any percentage, so a domain at
`p=reject; pct=90` is between rungs and the engine has to decide which rung it
counts as.

It used to pick the FIRST rung of that policy, so a domain at 90 percent
counted as being at 25 percent, and the next step after that is 50. The advice
read "Nothing is failing. The next step is reject at 50%" and handed over a
record weakening the domain from 90 to 50, which is a downgrade presented as
progress.

The rung is now the highest one the domain has already passed.
"""

from __future__ import annotations

import pytest

from engine.dmarc.policy_engine import (
    LADDER,
    DmarcRecord,
    ReportSummary,
    Sender,
    SpfRecord,
    _ladder_index,
    evaluate,
)

RUA = "mailto:dmarc@example.com"


def _clean() -> ReportSummary:
    return ReportSummary(
        senders=[
            Sender(
                "Google Workspace",
                500,
                True,
                True,
                True,
                True,
                "legit",
                "none",
                classification="clean",
            )
        ],
        total_volume=500,
    )


def _spf() -> SpfRecord:
    return SpfRecord(exists=True, record_count=1, lookups=3, all_qualifier="-")


def _advice(p: str, pct: int):
    return evaluate(DmarcRecord(exists=True, p=p, sp=p, pct=pct), _spf(), _clean(), RUA).primary


def _pct_of(record: str) -> int:
    """The percentage in a record, or 100 when it names none."""
    for part in record.split(";"):
        key, _, value = part.strip().partition("=")
        if key.strip() == "pct":
            return int(value)
    return 100


# ── the bug ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("policy", "pct"),
    [
        ("reject", 90),
        ("reject", 75),
        ("reject", 51),
        ("quarantine", 99),
        ("quarantine", 75),
        ("quarantine", 51),
    ],
)
def test_the_next_step_never_weakens_the_record(policy: str, pct: int) -> None:
    """The one that matters. A step that lowers the percentage is a downgrade,
    and calling it the next step sends a careful sender backwards."""
    advice = _advice(policy, pct)
    if advice.new_record is None:
        return
    assert _pct_of(advice.new_record) > pct, (
        f"at p={policy}; pct={pct} the advice offers {advice.new_record!r}, "
        f"which is weaker than what they already publish"
    )


@pytest.mark.parametrize(
    ("policy", "pct", "expected"),
    [
        ("reject", 90, ("reject", 50)),
        ("reject", 75, ("reject", 50)),
        ("reject", 50, ("reject", 50)),
        ("reject", 26, ("reject", 25)),
        ("quarantine", 99, ("quarantine", 50)),
        ("quarantine", 75, ("quarantine", 50)),
        ("quarantine", 26, ("quarantine", 25)),
    ],
)
def test_an_off_rung_record_counts_as_the_highest_rung_it_passed(
    policy: str, pct: int, expected: tuple[str, int]
) -> None:
    assert LADDER[_ladder_index(DmarcRecord(exists=True, p=policy, sp=policy, pct=pct))] == expected


def test_below_the_lowest_rung_counts_as_the_rung_below() -> None:
    """A domain at quarantine 10 has not reached quarantine 25, so that rung is
    still ahead of it and is what it should be offered next. Counting it as
    already there would skip it and offer 50."""
    assert LADDER[_ladder_index(DmarcRecord(exists=True, p="quarantine", sp="q", pct=10))] == (
        "none",
        0,
    )
    advice = _advice("quarantine", 10)
    assert advice.new_record is not None
    assert _pct_of(advice.new_record) == 25


# ── what must not change ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("policy", "pct", "rung"),
    [
        ("none", 0, 0),
        ("none", 100, 0),
        ("quarantine", 25, 1),
        ("quarantine", 100, 3),
        ("reject", 25, 4),
        ("reject", 100, 6),
    ],
)
def test_a_record_already_on_a_rung_is_unmoved(policy: str, pct: int, rung: int) -> None:
    assert _ladder_index(DmarcRecord(exists=True, p=policy, sp=policy, pct=pct)) == rung


def test_no_record_at_all_is_below_the_ladder() -> None:
    assert _ladder_index(DmarcRecord(exists=False)) == -1


def test_a_policy_nobody_recognises_counts_as_the_bottom() -> None:
    """A malformed p= should not crash the ladder, and the bottom is the safe
    place to put it: the advice then walks them up from the start."""
    assert _ladder_index(DmarcRecord(exists=True, p="banana", sp="banana", pct=100)) == 0


def test_the_top_of_the_ladder_is_still_the_end() -> None:
    assert _advice("reject", 100).code == "AT_GOAL"
