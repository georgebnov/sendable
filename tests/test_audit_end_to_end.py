"""The audit entry point, driven the way a caller drives it.

These tests call `audit()` on a whole email and assert on the report it returns.
They are the only tests that exercise the fan-out, the scoring, and the verdict
together, so they catch a check that crashes or a score that moves for no reason.

Network checks are off and no model is reachable, so every run is deterministic.
"""

from __future__ import annotations

import pytest

from engine.parse import parse_eml
from engine.report import Report
from engine.runner import audit
from engine.severity import SCORE_GO_MIN, SCORE_REVIEW_MIN
from tests.conftest import load


async def _audit(name: str) -> Report:
    return await audit(parse_eml(load(name)), domain_health=False)


# ── the report holds together ──────────────────────────────────────────────


async def test_report_shape_is_complete() -> None:
    report = await _audit("clean_bulk.eml")
    assert 0 <= report.score <= 100
    assert report.verdict in {"GO", "REVIEW", "NO_GO"}
    assert report.findings, "an audit with no findings means the fan-out did not run"
    assert report.from_addr == "Jane Okafor <jane@example.com>"
    assert report.subject == "Your March water bill dropped 18 percent"


async def test_every_finding_is_well_formed() -> None:
    # A check that returns a malformed finding breaks the report for a caller,
    # and the fan-out would otherwise hide it behind an aggregate score.
    report = await _audit("broken_bulk.eml")
    for f in report.findings:
        assert f.check, "every finding names the check that produced it"
        assert f.message, f"{f.check} returned an empty message"
        assert isinstance(f.passed, bool)
        assert f.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


async def test_check_names_are_unique_per_report() -> None:
    # Two findings under one name means a caller cannot address either of them.
    report = await _audit("clean_bulk.eml")
    names = [f.check for f in report.findings]
    duplicates = {n for n in names if names.count(n) > 1}
    assert not duplicates, f"duplicate check names: {sorted(duplicates)}"


# ── the verdict tracks the email ───────────────────────────────────────────


async def test_a_broken_send_scores_below_a_clean_one() -> None:
    clean = await _audit("clean_bulk.eml")
    broken = await _audit("broken_bulk.eml")
    assert broken.score < clean.score, (
        f"the broken fixture scored {broken.score} and the clean one {clean.score}; "
        "the scorer is not separating them"
    )


async def test_the_broken_send_is_not_cleared_to_send() -> None:
    report = await _audit("broken_bulk.eml")
    assert report.verdict == "NO_GO"
    assert report.score < SCORE_REVIEW_MIN


async def test_the_verdict_matches_the_score_thresholds() -> None:
    for name in ("clean_bulk.eml", "broken_bulk.eml"):
        report = await _audit(name)
        if report.score >= SCORE_GO_MIN:
            assert report.verdict == "GO"
        elif report.score >= SCORE_REVIEW_MIN:
            assert report.verdict == "REVIEW"
        else:
            assert report.verdict == "NO_GO"


# ── the specific problems in the broken fixture are caught ─────────────────


@pytest.mark.parametrize(
    ("check", "reason"),
    [
        ("headers.required_headers", "the fixture has no Message-ID and no Date"),
        ("content.hidden_css_salting", "the fixture hides text with display:none"),
        ("auth.dmarc_alignment_overall", "the fixture carries no authentication at all"),
    ],
)
async def test_broken_fixture_fails_the_expected_check(check: str, reason: str) -> None:
    report = await _audit("broken_bulk.eml")
    found = [f for f in report.findings if f.check == check]
    assert found, f"{check} did not run at all"
    assert not found[0].passed, f"{check} passed, but {reason}"


async def test_a_hard_gate_failure_is_recorded_on_the_report() -> None:
    # A hard gate caps the score no matter how clean the rest is, so the report
    # must name which gate failed or the number is unexplainable.
    report = await _audit("broken_bulk.eml")
    assert report.hard_gates_failed


# ── the clean fixture is not punished for things it does right ─────────────


@pytest.mark.parametrize(
    ("check", "reason"),
    [
        ("auth.spf", "the fixture reports spf=pass"),
        ("auth.dkim", "the fixture reports dkim=pass"),
        ("auth.dmarc", "the fixture reports dmarc=pass"),
        ("content.plain_text_alternative", "the fixture carries a text/plain part"),
    ],
)
async def test_clean_fixture_passes_the_expected_check(check: str, reason: str) -> None:
    report = await _audit("clean_bulk.eml")
    found = [f for f in report.findings if f.check == check]
    assert found, f"{check} did not run at all"
    assert found[0].passed, f"{check} failed, but {reason}: {found[0].message}"


# ── sub-scores ─────────────────────────────────────────────────────────────


async def test_sub_scores_are_reported_in_range() -> None:
    report = await _audit("clean_bulk.eml")
    assert report.sub_scores, "a report with no sub-scores cannot explain its total"
    for name, value in report.sub_scores.items():
        assert 0 <= value <= 100, f"sub-score {name} is {value}"


# ── the audit never raises on hostile input ────────────────────────────────


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"From: a@b.c\r\n\r\n",
        b"Subject: no from header\r\n\r\nbody",
        b"\x00\x01\x02 not an email at all",
        b"From: \r\nTo: \r\nSubject: \r\n\r\n",
    ],
    ids=["empty", "minimal", "no-from", "binary-junk", "blank-headers"],
)
async def test_degenerate_input_returns_a_report_instead_of_raising(raw: bytes) -> None:
    # An agent will feed this whatever it has. A crash is a worse answer than a
    # low score, because a crash tells the caller nothing.
    report = await audit(parse_eml(raw), domain_health=False)
    assert isinstance(report, Report)
    assert 0 <= report.score <= 100
