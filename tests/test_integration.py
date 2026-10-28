"""The whole chain, end to end: an .eml file in, a scored verdict out.

This is the MVP contract. The tool answers one question, "will this land", and
it answers it from the file alone. No history, no stored state, no second run
needed. So this test audits the two fixtures and checks the thing a user acts
on: the verdict, the sub-scores behind it, and the findings that explain it.

It also pins what the tool must NOT do any more. An audit writes nothing to
disk, and no finding may come from a comparison against an earlier send, because
there is nothing left to compare against.
"""

from __future__ import annotations

import pathlib

from engine.parse import parse_eml
from engine.report import Report
from engine.runner import audit

from .conftest import load


async def _audit(name: str) -> Report:
    # domain_health=False keeps the suite off the network, per rule 4.
    return await audit(parse_eml(load(name)), domain_health=False)


async def test_a_clean_bulk_email_is_a_go() -> None:
    report = await _audit("clean_bulk.eml")
    assert report.verdict == "GO", f"scored {report.score}"
    assert report.score >= 85
    assert not report.hard_gates_failed


async def test_a_broken_bulk_email_is_not_a_go() -> None:
    report = await _audit("broken_bulk.eml")
    assert report.verdict in {"REVIEW", "NO_GO"}, f"scored {report.score}"
    assert report.score < 85
    # The point of the tool is the reason, not the number. A failing verdict with
    # no failing finding would give a user nothing to act on.
    assert [f for f in report.findings if not f.passed]


async def test_the_verdict_matches_the_documented_bands() -> None:
    # GO at 85 and above, REVIEW at 65, NO_GO below that. SKILL.md and README.md
    # both state these numbers, so a change here is a change to the contract.
    for name in ("clean_bulk.eml", "broken_bulk.eml"):
        r = await _audit(name)
        expected = "GO" if r.score >= 85 else "REVIEW" if r.score >= 65 else "NO_GO"
        assert r.verdict == expected, f"{name}: {r.score} gave {r.verdict}"


async def test_every_finding_carries_a_message_a_user_can_read() -> None:
    for name in ("clean_bulk.eml", "broken_bulk.eml"):
        for f in (await _audit(name)).findings:
            assert f.message.strip(), f"{name}: {f.check} has no message"


async def test_no_finding_compares_against_an_earlier_send() -> None:
    # The 6 drift checks are gone with the store. A `drift.*` id reappearing
    # means history crept back in, and it cannot work without the store.
    for name in ("clean_bulk.eml", "broken_bulk.eml"):
        drift = [f.check for f in (await _audit(name)).findings if f.check.startswith("drift.")]
        assert not drift, f"{name}: {drift}"


async def test_an_audit_writes_nothing_to_disk(tmp_path, monkeypatch) -> None:
    # Run from an empty directory. The audit used to create .sendable/ here.
    monkeypatch.chdir(tmp_path)
    await _audit("clean_bulk.eml")
    assert list(tmp_path.iterdir()) == [], f"audit created {list(tmp_path.iterdir())}"


async def test_the_same_email_audits_the_same_way_twice() -> None:
    # Without a store there is no first-run versus second-run difference. A
    # second audit of the same bytes must return the same score.
    first = await _audit("clean_bulk.eml")
    second = await _audit("clean_bulk.eml")
    assert first.score == second.score
    assert first.verdict == second.verdict
    assert [f.check for f in first.findings] == [f.check for f in second.findings]


def test_the_store_is_gone() -> None:
    # The package and the reports CLI are deleted, not merely unused.
    assert not pathlib.Path("store").exists()
    assert not pathlib.Path("engine/drift").exists()
    assert not pathlib.Path("engine/history.py").exists()
    assert not pathlib.Path("scripts/reports.py").exists()
