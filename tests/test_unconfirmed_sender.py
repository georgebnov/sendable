"""A source that proved its own identity is a question, not a spoof.

An email tool nobody put on the curated list, set up without the user's domain,
passes DKIM and SPF on its own domain and aligns with nothing. It was labelled a
spoof, a spoof does not block, so the tool said "Nothing is failing" and handed
over a quarantine record that would filter the user's real mail.

`tests/fixtures/dmarc_unknown_esp.xml` is that report: 4,200 of 6,235 messages
from such a source, and 85 from a source where nothing authenticates.
"""

from __future__ import annotations

import itertools
import json
import pathlib
import runpy
import sys
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import pytest

from engine.dmarc import dns_records
from engine.dmarc.classifier import classify_record
from engine.dmarc.parser import (
    AuthResult,
    DmarcPolicyPublished,
    DmarcRecord,
    DmarcReport,
)
from engine.dmarc.policy_engine import (
    DmarcRecord as PublishedDmarc,
)
from engine.dmarc.policy_engine import (
    EngineResult,
    ReportSummary,
    Sender,
    SpfRecord,
    _fixable_blockers,
    _is_blocker,
    evaluate,
)
from engine.dmarc.summary import summarise_reports

ROOT = pathlib.Path(__file__).parent.parent
PROBE = pathlib.Path(__file__).parent / "fixtures" / "dmarc_unknown_esp.xml"
DOMAIN = "example.com"
TOOL = "esp.example.net"
SPF = SpfRecord(True, 1, 1, "-")
RUA = f"mailto:dmarc@{DOMAIN}"


def _row(
    ip: str,
    count: int,
    *,
    dkim: tuple[str, str] | None = None,
    spf: tuple[str, str] | None = None,
    policy: str = "fail",
    disposition: str = "none",
) -> DmarcRecord:
    """One report row. `dkim` and `spf` are (domain, result) pairs."""
    return DmarcRecord(
        source_ip=ip,
        count=count,
        disposition=disposition,
        policy_dkim=policy,
        policy_spf=policy,
        header_from=DOMAIN,
        envelope_from=spf[0] if spf else "elsewhere.example.org",
        auth_dkim=[AuthResult(domain=dkim[0], result=dkim[1])] if dkim else [],
        auth_spf=[AuthResult(domain=spf[0], result=spf[1])] if spf else [],
    )


def _tool_row(count: int, ip: str = "192.0.2.44", disposition: str = "none") -> DmarcRecord:
    return _row(
        ip,
        count,
        dkim=(TOOL, "pass"),
        spf=(f"bounces.{TOOL}", "pass"),
        disposition=disposition,
    )


def _clean_row(count: int, ip: str = "198.51.100.10") -> DmarcRecord:
    return _row(ip, count, dkim=(DOMAIN, "pass"), spf=(DOMAIN, "pass"), policy="pass")


def _spoof_row(count: int, disposition: str = "none") -> DmarcRecord:
    return _row(
        "198.51.100.200",
        count,
        spf=("attacker.example.org", "fail"),
        disposition=disposition,
    )


def _report(*records: DmarcRecord, p: str = "none") -> DmarcReport:
    return DmarcReport(
        org_name="mail.example.org",
        report_id="r1",
        date_begin=datetime(2026, 9, 1, tzinfo=UTC),
        date_end=datetime(2026, 9, 1, 23, 59, tzinfo=UTC),
        policy=DmarcPolicyPublished(domain=DOMAIN, p=p, adkim="r", aspf="r"),
        records=list(records),
    )


def _tool_in(*records: DmarcRecord) -> Sender:
    """The one sender in these rows that proved an identity of its own."""
    summary = summarise_reports([_report(*records)], domain=DOMAIN)
    return next(s for s in summary.senders if s.authenticated_as)


def _decide(
    *records: DmarcRecord,
    p: str = "none",
    pct: int = 100,
    not_mine: frozenset[str] = frozenset(),
) -> EngineResult:
    summary = summarise_reports([_report(*records, p=p)], domain=DOMAIN, not_mine=not_mine)
    return evaluate(PublishedDmarc(True, p, pct=pct), SPF, summary, RUA)


def _run_cli(
    argv: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> tuple[dict[str, Any], str]:
    """The real entry point, with the two TXT answers a reserved name cannot get."""
    zone = {
        "alderpine.example": ["v=spf1 ip4:198.51.100.10 include:esp.example.net -all"],
        "_dmarc.alderpine.example": ["v=DMARC1; p=none; rua=mailto:dmarc@alderpine.example"],
    }
    monkeypatch.setattr(dns_records, "_query_txt", lambda name: zone.get(name, []))
    monkeypatch.setattr(sys, "argv", ["dmarc.py", *argv])
    with pytest.raises(SystemExit) as stopped:
        runpy.run_path(str(ROOT / "scripts" / "dmarc.py"), run_name="__main__")
    assert stopped.value.code == 0
    captured = capsys.readouterr()
    return json.loads(captured.out), captured.err


# --- the report that found the bug ---------------------------------------------


def test_the_probe_report_does_not_advance(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    out, _ = _run_cli([str(PROBE)], monkeypatch, capsys)
    step = out["next_step"]
    assert step["code"] == "CONFIRM_SENDER"
    assert step["new_record"] is None, "no record to paste until the sender is known"
    assert "Nothing is failing" not in step["title"]
    assert [s["authenticated_as"] for s in out["blockers"]] == ["example.net"]
    assert out["blockers"][0]["volume"] == 4200
    assert out["blockers"][0]["legitimacy"] == "unconfirmed"


def test_the_probe_report_keeps_its_true_spoof_a_spoof(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    out, _ = _run_cli([str(PROBE)], monkeypatch, capsys)
    spoof = next(s for s in out["senders"] if s["volume"] == 85)
    assert spoof["classification"] == "spoofing_delivered"
    assert spoof["legitimacy"] == "suspicious"
    assert spoof not in out["blockers"]


def test_the_advice_names_a_next_step_a_user_can_take(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    out, _ = _run_cli([str(PROBE)], monkeypatch, capsys)
    step = out["next_step"]
    action = step["suggested_action"]
    assert "--not-mine example.net" in action
    assert "DKIM" in action
    text = f"{step['title']} {step['detail']} {action}"
    assert " - " not in text
    assert not {chr(0x2013), chr(0x2014)} & set(text), "no dashes in text a user reads"
    assert "RFC" not in text


# --- which rows get the label ---------------------------------------------------


@pytest.mark.parametrize("disposition", ["none", "quarantine", "reject"])
def test_a_source_passing_on_its_own_domain_is_not_a_spoof(disposition: str) -> None:
    """Every disposition. A label that held only at p=none would flip to "spoof
    blocked, working as intended" on the first rung, while real mail is filtered."""
    row = _tool_row(10, disposition=disposition)
    assert classify_record(row).classification == "unconfirmed_sender"


@pytest.mark.parametrize(
    "row",
    [
        _row("192.0.2.44", 10, dkim=(TOOL, "pass")),
        _row("192.0.2.44", 10, spf=(TOOL, "pass")),
        _row("192.0.2.44", 10, dkim=(TOOL, "fail"), spf=(TOOL, "pass")),
    ],
    ids=["dkim-only", "spf-only", "dkim-fails-spf-passes"],
)
def test_one_passing_check_is_enough(row: DmarcRecord) -> None:
    assert classify_record(row).classification == "unconfirmed_sender"


def test_a_failed_signature_of_yours_does_not_excuse_a_source() -> None:
    """A failed signature on the user's own domain looks like a forward, but
    anyone can attach one, so it must not switch the question off."""
    row = _row("192.0.2.44", 10, dkim=(DOMAIN, "fail"), spf=("forwarder.example.org", "pass"))
    assert classify_record(row).classification == "unconfirmed_sender"


@pytest.mark.parametrize(
    ("disposition", "label"),
    [("none", "spoofing_delivered"), ("reject", "spoofing_blocked")],
)
def test_nothing_authenticating_stays_a_spoof(disposition: str, label: str) -> None:
    assert classify_record(_spoof_row(10, disposition)).classification == label


def test_a_pass_with_no_domain_proves_nothing() -> None:
    row = _row("192.0.2.44", 10, dkim=("", "pass"))
    assert classify_record(row).classification == "spoofing_delivered"


def test_a_pass_on_your_own_domain_is_not_someone_elses_identity() -> None:
    """The question is "who is this other domain". A row that names no other
    domain has nothing to ask about, and the user cannot dismiss their own."""
    row = _row("192.0.2.44", 10, dkim=(f"mail.{DOMAIN}", "pass"), disposition="reject")
    assert classify_record(row).classification == "spoofing_blocked"


# --- volume, and grouping -------------------------------------------------------


def test_one_provider_on_many_addresses_is_one_sender() -> None:
    """Each address alone is 5 percent. Judged per address, a provider that
    spreads its mail thin would never reach the threshold."""
    rows = [_tool_row(5, ip=f"192.0.2.{n}") for n in range(1, 11)]
    tool = _tool_in(*rows, _clean_row(50))
    assert tool.volume == 50
    assert tool.legitimacy == "unconfirmed"
    assert _is_blocker(tool)


def test_a_fifth_of_the_volume_is_material() -> None:
    tool = _tool_in(_tool_row(20), _clean_row(80))
    assert tool.classification == "unconfirmed_sender"
    assert _is_blocker(tool)


def test_a_small_source_is_not_called_a_spoof_and_does_not_block() -> None:
    tool = _tool_in(_tool_row(19), _clean_row(81))
    assert tool.classification == "unconfirmed_low_volume"
    assert tool.legitimacy == "suspicious"
    assert not _is_blocker(tool)


def test_a_small_source_is_named_in_the_advice() -> None:
    """Most of these rows are forwards, and a domain cannot be held off the ladder
    by every one. It is not a confirmed spoof either, so the advice says its name."""
    step = _decide(_tool_row(19), _clean_row(81)).primary
    assert step.code == "ADVANCE"
    assert step.new_record is not None
    assert "Nothing is failing" not in step.title
    assert "example.net (19 message(s))" in step.detail


def test_a_spoof_flood_cannot_shrink_a_real_tool_below_the_share() -> None:
    """Spoofed mail is not the user's volume. Counted, it would let an attacker
    turn the question off by sending more, which is the bug this file is about."""
    step = _decide(_tool_row(4200), _spoof_row(30000), _clean_row(2000)).primary
    assert step.code == "CONFIRM_SENDER"
    assert step.new_record is None


def test_a_dismissed_source_does_not_shrink_the_next_one() -> None:
    """The user said that mail is not theirs, so it is not in the share either."""
    dismissed = _row("192.0.2.9", 9000, dkim=("not-mine.example.org", "pass"))
    rows = (dismissed, _tool_row(1000), _clean_row(3000))
    step = _decide(*rows, not_mine=frozenset({"example.org"})).primary
    assert step.code == "CONFIRM_SENDER"
    assert "example.net" in step.title


def test_a_clean_row_from_the_same_address_does_not_hide_the_source() -> None:
    """Merging on the address would take the best case on alignment, and one clean
    message would then clear every message that failed."""
    for rows in (
        (_tool_row(40, ip="192.0.2.44"), _clean_row(60, ip="192.0.2.44")),
        (_clean_row(60, ip="192.0.2.44"), _tool_row(40, ip="192.0.2.44")),
    ):
        assert _decide(*rows).primary.code == "CONFIRM_SENDER"


# --- what the ladder does with it -----------------------------------------------


@pytest.mark.parametrize(
    ("p", "pct"),
    [("quarantine", 25), ("quarantine", 100), ("reject", 50), ("reject", 100)],
)
def test_filtered_mail_from_an_unknown_source_never_weakens_the_policy(p: str, pct: int) -> None:
    """A throwaway domain can pass SPF. Rolling back for it would hand an attacker
    a weaker record, and calling it legitimate would be a guess."""
    filtered = _tool_row(60, disposition="quarantine" if p == "quarantine" else "reject")
    step = _decide(filtered, _clean_row(40), p=p, pct=pct).primary
    assert step.code == "CONFIRM_SENDER"
    assert step.new_record is None
    assert step.tier == "action"
    assert "is legitimate" not in step.detail
    assert "60 message(s)" in step.detail


def test_a_fix_for_a_known_sender_does_not_name_the_unconfirmed_one() -> None:
    known = _failing("sender_auth_gap", "unconfirmed", "reject")
    tool = _failing("unconfirmed_sender", "unconfirmed", "reject", authenticated_as="example.net")
    summary = ReportSummary(senders=[known, tool, _CLEAN], total_volume=150)
    result = evaluate(PublishedDmarc(True, "reject", pct=100), SPF, summary, RUA)
    assert result.ladder_decision is not None
    assert known.name in result.ladder_decision.detail
    assert tool.name not in result.ladder_decision.detail


def test_no_finding_says_the_unconfirmed_source_is_your_provider() -> None:
    """These two findings are HIGH, so they would outrank the question and answer
    it wrongly: both assert the source is a provider of yours."""
    for row in (_tool_row(60), _row("192.0.2.44", 60, dkim=(TOOL, "pass"))):
        codes = {f.code for f in _decide(row, _clean_row(40)).spf_findings}
        assert not codes & {"SPF_SENDER_UNALIGNED_NODKIM", "SPF_SENDER_NOT_AUTHORIZED"}


def test_a_filtered_relay_does_not_hide_the_question() -> None:
    """A recipient's gateway is filtered on most enforcing domains, so "nothing to
    fix on your side" would hold off the question for as long as that lasts."""
    relay = _failing("gateway_relay", "legit", "quarantine")
    tool = _failing("unconfirmed_sender", "unconfirmed", "none", authenticated_as="example.net")
    summary = ReportSummary(senders=[relay, tool, _CLEAN], total_volume=150)
    result = evaluate(PublishedDmarc(True, "quarantine", pct=25), SPF, summary, RUA)
    assert result.ladder_decision is not None
    assert result.ladder_decision.code == "CONFIRM_SENDER"


def test_a_small_source_is_named_at_full_enforcement() -> None:
    """Here the policy is rejecting it, so "nothing else to do" hides real mail."""
    step = _decide(_tool_row(19, disposition="reject"), _clean_row(81), p="reject").primary
    assert step.code == "AT_GOAL"
    assert "example.net (19 message(s))" in step.detail
    assert "nothing else to do" not in step.suggested_action


def test_a_small_source_is_not_called_an_impersonation_attempt() -> None:
    known = replace(_failing("sender_auth_gap", "unconfirmed", "reject"), volume=5)
    small = _failing("unconfirmed_low_volume", "suspicious", "none", authenticated_as="example.net")
    summary = ReportSummary(senders=[known, small, _CLEAN], total_volume=105)
    decision = evaluate(PublishedDmarc(True, "reject", pct=100), SPF, summary, RUA).ladder_decision
    assert decision is not None
    assert decision.code == "FIX_SENDER"
    assert "impersonation" not in decision.detail


def test_the_question_reads_true_at_full_enforcement() -> None:
    """There is no next rung, so the advice cannot speak of one."""
    step = _decide(_tool_row(60, disposition="reject"), _clean_row(40), p="reject").primary
    assert step.code == "CONFIRM_SENDER"
    text = f"{step.title} {step.detail}"
    assert "advance" not in text
    assert "next step" not in text
    assert "stronger" not in text


def test_the_advice_says_older_reports_keep_the_question_open() -> None:
    """Rows from before the fix stay in their own sender, so a user who passes
    every report they have would stay blocked after doing what the advice said."""
    fixed = _row(
        "192.0.2.44",
        4000,
        dkim=(DOMAIN, "pass"),
        spf=(f"bounces.{TOOL}", "pass"),
        policy="pass",
    )
    step = _decide(_tool_row(4000), fixed, _clean_row(1000)).primary
    assert step.code == "CONFIRM_SENDER"
    assert "older" in step.suggested_action


def test_two_sources_are_answered_one_at_a_time() -> None:
    """One flag line for both would mark a real tool a spoof along with the other."""
    other = _row("192.0.2.45", 40, dkim=("other.example.org", "pass"))
    action = _decide(_tool_row(40), other, _clean_row(20)).primary.suggested_action
    assert "--not-mine example.net" in action
    assert "--not-mine example.org" in action
    assert "--not-mine example.net --not-mine" not in action


def test_a_row_with_no_from_domain_never_names_your_own_domain() -> None:
    """The report still says whose domain it is about."""
    row = replace(_row("192.0.2.44", 10, dkim=(DOMAIN, "pass")), header_from=None)
    assert classify_record(row, _report().policy).classification == "spoofing_delivered"


# --- the way out ----------------------------------------------------------------


def test_not_mine_clears_the_block_and_marks_a_spoof(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    out, _ = _run_cli([str(PROBE), "--not-mine", "example.net"], monkeypatch, capsys)
    assert out["next_step"]["code"] == "ADVANCE"
    assert out["next_step"]["new_record"]
    assert out["blockers"] == []
    assert out["not_mine"] == ["example.net"]
    tool = next(s for s in out["senders"] if s["volume"] == 4200)
    assert tool["classification"] == "spoofing_delivered"
    assert tool["legitimacy"] == "suspicious"


def test_not_mine_accepts_the_domain_a_user_reads_in_the_report(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    out, _ = _run_cli([str(PROBE), "--not-mine", "Bounces.ESP.example.net."], monkeypatch, capsys)
    assert out["not_mine"] == ["example.net"]
    assert out["next_step"]["code"] == "ADVANCE"


def test_not_mine_with_no_match_changes_nothing_and_says_so(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    out, err = _run_cli([str(PROBE), "--not-mine", "typo.example.org"], monkeypatch, capsys)
    assert out["next_step"]["code"] == "CONFIRM_SENDER"
    assert out["not_mine"] == []
    assert "typo.example.org" in err
    assert "example.net" in err, "the warning names what could have matched"


def test_not_mine_applies_at_full_enforcement() -> None:
    rows = (_tool_row(60, disposition="reject"), _clean_row(40))
    assert _decide(*rows, p="reject").primary.code == "CONFIRM_SENDER"
    done = _decide(*rows, p="reject", not_mine=frozenset({"example.net"}))
    assert done.primary.code == "AT_GOAL"


# --- the guard ------------------------------------------------------------------

_CLEAN = Sender("Clean", 50, True, True, True, True, "legit", "none", classification="clean")


def _failing(
    classification: str,
    legitimacy: str,
    disposition: str,
    *,
    authenticated_as: str | None = None,
) -> Sender:
    return Sender(
        f"Sender {classification}",
        50,
        False,
        False,
        True,
        True,
        legitimacy,
        disposition,
        classification=classification,
        authenticated_as=authenticated_as,
    )


_FAILING_KINDS = [
    ("sender_auth_gap", "unconfirmed", None),
    ("unconfirmed_sender", "unconfirmed", "example.net"),
    ("unconfirmed_low_volume", "suspicious", "example.net"),
    ("spoofing_delivered", "suspicious", None),
    ("spoofing_blocked", "suspicious", None),
    ("gateway_relay", "legit", None),
    ("forwarding_artifact", "legit", None),
    ("bounce", "legit", None),
    ("policy_override_sampled", "legit", None),
    ("unclassified", "unconfirmed", None),
]
_MIXES = [c for size in (0, 1, 2) for c in itertools.combinations(_FAILING_KINDS, size)]


@pytest.mark.parametrize(
    ("p", "pct"),
    [("none", 100), ("quarantine", 25), ("quarantine", 100), ("reject", 25), ("reject", 100)],
)
@pytest.mark.parametrize("disposition", ["none", "quarantine", "reject"])
@pytest.mark.parametrize("mix", _MIXES)
def test_the_advice_never_claims_nothing_fails_while_a_sender_fails(
    p: str, pct: int, disposition: str, mix: tuple[tuple[str, str, str | None], ...]
) -> None:
    """Every mix of failing senders, on every kind of record.

    The claim is the one thing a user acts on without reading further, so it holds
    only when every sender in the reports aligns. A sender that blocks must also
    never reach a result that hands over a stronger record or says "done".
    """
    senders = [_CLEAN] + [
        _failing(tag, legitimacy, disposition, authenticated_as=seen)
        for tag, legitimacy, seen in mix
    ]
    summary = ReportSummary(senders=senders, total_volume=sum(s.volume for s in senders))
    decision = evaluate(PublishedDmarc(True, p, pct=pct), SPF, summary, RUA).ladder_decision
    assert decision is not None

    if "Nothing is failing" in decision.title:
        assert all(s.dmarc_aligned for s in senders), (
            f"{decision.title!r} while {[s.name for s in senders if not s.dmarc_aligned]} "
            "fail. In engine/dmarc/policy_engine.py, say this only when every sender aligns."
        )

    if _fixable_blockers([s for s in senders if _is_blocker(s)]):
        assert decision.code not in ("ADVANCE", "AT_GOAL"), (
            f"{decision.code} while a sender blocks. In engine/dmarc/policy_engine.py, "
            "check _is_blocker and the order of the branches in dmarc_decision."
        )
