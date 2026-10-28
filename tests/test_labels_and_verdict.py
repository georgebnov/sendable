"""The two smallest pieces of user-facing judgement: the label and the verdict.

Both are read by a person rather than by code, and both have a branch that only
fires on input nobody thought about. A check with no curated label still has to
render as something a marketer can read, and the verdict has to say NO_GO on a
CRITICAL finding no matter how high the score climbed.
"""

from __future__ import annotations

import pytest

from engine.check_labels import CHECK_LABELS, label_for
from engine.severity import SCORE_GO_MIN, SCORE_REVIEW_MIN, Severity, verdict

# ── labels ────────────────────────────────────────────────────────────


def test_a_curated_label_is_used_as_written() -> None:
    assert label_for("auth.spf") == CHECK_LABELS["auth.spf"]


def test_an_uncurated_check_still_renders_as_a_readable_phrase() -> None:
    # The map cannot be kept exhaustive, so a new check must not surface its
    # wire key to a marketer. The prefix goes and the underscores become spaces.
    assert label_for("copywriting.something_clever") == "Something clever"


def test_a_check_id_with_no_prefix_is_prettified_whole() -> None:
    # Without this the partition returns an empty tail and the label is "".
    assert label_for("standalone_check") == "Standalone check"


def test_only_the_first_letter_is_capitalised() -> None:
    # `.capitalize()` lowercases the rest, which is what keeps a wire key like
    # `dkim_record.key_bits` from rendering as "Key Bits".
    assert label_for("dkim_record.some_NEW_thing") == "Some new thing"


def test_every_curated_label_is_a_non_empty_string() -> None:
    # A blank label renders as nothing at all in a report.
    assert CHECK_LABELS
    for check, text in CHECK_LABELS.items():
        assert text.strip(), f"{check} has a blank label"


# ── the verdict ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (100, "GO"),
        (SCORE_GO_MIN, "GO"),
        (SCORE_GO_MIN - 1, "REVIEW"),
        (SCORE_REVIEW_MIN, "REVIEW"),
        (SCORE_REVIEW_MIN - 1, "NO_GO"),
        (0, "NO_GO"),
    ],
)
def test_the_bands_are_inclusive_at_their_lower_edge(score: int, expected: str) -> None:
    # 85 is GO and 84 is REVIEW. README.md and SKILL.md both publish these
    # numbers, so an off-by-one here contradicts the documentation.
    assert verdict(score, has_critical=False) == expected


@pytest.mark.parametrize("score", [100, 90, SCORE_GO_MIN, 50, 0])
def test_a_critical_finding_forces_no_go_at_any_score(score: int) -> None:
    # The whole point of a hard gate. A perfect score with a CRITICAL finding is
    # still a message that should not be sent.
    assert verdict(score, has_critical=True) == "NO_GO"


def test_the_severity_order_runs_worst_first() -> None:
    # Reports sort findings by this order, so a reader sees the worst first.
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    assert [s.value for s in order] == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def test_a_severity_compares_equal_to_its_own_name() -> None:
    # Severity is a StrEnum, and the stored JSON carries the plain string. A
    # report read back from disk has to compare against the enum.
    assert Severity.HIGH == "HIGH"
    assert Severity.INFO != "HIGH"
