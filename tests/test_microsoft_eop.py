"""Reading Microsoft's own verdict out of the headers it stamps.

Exchange Online writes `X-Microsoft-Antispam` and `X-Forefront-Antispam-Report`
onto every message it handles. Those headers say what Microsoft decided: a spam
confidence level, a bulk complaint level, a filter verdict, and whether composite
authentication passed.

This is the most direct evidence an audit can have. Everything else predicts how a
receiver will treat a message; these headers record how one already did. Reading
them wrong means reporting a message as clean that Microsoft already junked.
"""

from __future__ import annotations

import asyncio

import pytest

from engine.domain.integrity import microsoft_eop
from engine.parse import ParsedEmail, parse_eml
from engine.report import Finding


# Where Exchange Online actually puts each value, which is not obvious and which
# I got wrong on the first attempt:
#   X-Forefront-Antispam-Report   CIP, SCL, SFV, CAT, compauth is NOT here
#   X-Microsoft-Antispam          BCL
#   Authentication-Results        compauth=<verdict> reason=<code>
def _email(*header_lines: str) -> ParsedEmail:
    raw = (
        "From: Jane <jane@example.com>\r\nTo: reader@example.com\r\n"
        "Subject: Open house Saturday\r\n"
        + "".join(f"{line}\r\n" for line in header_lines)
        + "\r\nThe open house runs from noon.\r\n"
    ).encode()
    return parse_eml(raw)


def _run(email: ParsedEmail) -> list[Finding]:
    return asyncio.run(microsoft_eop.run(email))


def _by(findings: list[Finding], suffix: str) -> Finding | None:
    for f in findings:
        if f.check.endswith(suffix):
            return f
    return None


# ── mail that never touched Microsoft ──────────────────────────────────────


def test_a_message_with_no_eop_headers_is_not_graded() -> None:
    # Most mail never transits Microsoft. Reporting a missing verdict as a problem
    # would fail every message sent to Gmail.
    findings = _run(_email())
    assert findings
    assert all(f.passed for f in findings)
    assert "did not transit" in findings[0].message


# ── the spam confidence level ──────────────────────────────────────────────


@pytest.mark.parametrize(
    ("scl", "passed"),
    [(-1, True), (0, True), (1, True), (5, False), (6, False), (7, False), (9, False)],
)
def test_the_spam_confidence_level_decides_the_verdict(scl: int, passed: bool) -> None:
    findings = _run(_email(f"X-Forefront-Antispam-Report: CIP:1.2.3.4;SCL:{scl};SFV:NSPM"))
    scl_finding = _by(findings, ".scl")
    assert scl_finding is not None, f"SCL:{scl} produced no finding"
    assert scl_finding.passed is passed


def test_a_high_confidence_spam_score_is_high_severity() -> None:
    # SCL 7 and above means Microsoft quarantines on Standard or Strict policy,
    # so the mail is not reaching the inbox at all.
    finding = _by(_run(_email("X-Forefront-Antispam-Report: CIP:1.2.3.4;SCL:7")), ".scl")
    assert finding is not None
    assert finding.severity == "HIGH"


def test_a_negative_score_means_filtering_was_bypassed() -> None:
    # A negative SCL is a Safe Sender or mail-flow rule, not a clean reputation.
    # Reading it as "very clean" would overstate how the message did.
    finding = _by(_run(_email("X-Forefront-Antispam-Report: CIP:1.2.3.4;SCL:-1")), ".scl")
    assert finding is not None
    assert finding.passed is True
    assert "bypass" in finding.message.lower()


# ── the bulk complaint level ───────────────────────────────────────────────


@pytest.mark.parametrize(("bcl", "passed"), [(0, True), (3, True), (5, False), (9, False)])
def test_the_bulk_complaint_level_is_graded(bcl: int, passed: bool) -> None:
    finding = _by(_run(_email(f"X-Microsoft-Antispam: BCL:{bcl};")), ".bcl")
    assert finding is not None, f"BCL:{bcl} produced no finding"
    assert finding.passed is passed


def test_the_default_bulk_threshold_is_named() -> None:
    # 7 is the default policy threshold, and a sender sitting at 5 needs to know
    # how much room is left before Microsoft starts junking.
    finding = _by(_run(_email("X-Microsoft-Antispam: BCL:5;")), ".bcl")
    assert finding is not None
    assert "7" in finding.message


# ── the filter verdict ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("sfv", "passed"),
    [("NSPM", True), ("SKA", True), ("SKQ", True), ("SPM", False), ("BLK", False)],
)
def test_the_filter_verdict_is_read(sfv: str, passed: bool) -> None:
    finding = _by(_run(_email(f"X-Forefront-Antispam-Report: CIP:1.2.3.4;SFV:{sfv}")), ".sfv")
    assert finding is not None, f"SFV:{sfv} produced no finding"
    assert finding.passed is passed


@pytest.mark.parametrize("sfv", ["PHSH", "AAD"])
def test_a_phishing_verdict_is_critical(sfv: str) -> None:
    # Microsoft calling a message phishing is the strongest negative signal in any
    # header this tool reads.
    finding = _by(_run(_email(f"X-Forefront-Antispam-Report: SFV:{sfv}")), ".sfv")
    assert finding is not None
    assert finding.severity == "CRITICAL"
    assert finding.passed is False


def test_an_unrecognised_verdict_does_not_raise() -> None:
    findings = _run(_email("X-Forefront-Antispam-Report: SFV:ZZZZ"))
    assert findings


# ── composite authentication ───────────────────────────────────────────────


@pytest.mark.parametrize(
    ("value", "passed"),
    [("pass", True), ("softpass", False), ("none", False), ("fail", False)],
)
def test_composite_authentication_is_graded(value: str, passed: bool) -> None:
    finding = _by(
        _run(
            _email(
                "X-Forefront-Antispam-Report: CIP:1.2.3.4;SCL:1",
                f"Authentication-Results: spf=pass; dkim=pass; dmarc=pass; compauth={value} reason=100",
            )
        ),
        ".compauth",
    )
    assert finding is not None, f"compauth={value} produced no finding"
    assert finding.passed is passed


def test_a_composite_authentication_failure_is_high() -> None:
    # compauth=fail means Microsoft does not trust the combination of SPF, DKIM
    # and DMARC it saw, whatever the individual results said.
    finding = _by(
        _run(
            _email(
                "X-Forefront-Antispam-Report: CIP:1.2.3.4;SCL:1",
                "Authentication-Results: spf=pass; dkim=fail; dmarc=fail; compauth=fail reason=001",
            )
        ),
        ".compauth",
    )
    assert finding is not None
    assert finding.severity == "HIGH"


# ── malformed headers ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "header",
    [
        "X-Microsoft-Antispam: ",
        "X-Forefront-Antispam-Report: SCL:not-a-number",
        "X-Microsoft-Antispam: BCL:;SCL:;",
        "X-Forefront-Antispam-Report: garbage without any tags",
        "Authentication-Results: compauth=",
    ],
)
def test_a_malformed_header_does_not_raise(header: str) -> None:
    # These headers come from a third party and an audit must survive whatever
    # arrives, including a truncated or rewritten one.
    assert _run(_email(header)) is not None
