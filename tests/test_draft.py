"""Grading an email that has not been sent yet.

An agent writing an email has a draft. It does not have a delivered message, and
about a third of the audit reads headers that only exist after a message has been
sent and received: Authentication-Results, DKIM-Signature, Return-Path, Received,
and the Date and Message-ID the sending server adds.

Graded as if it were a real send, a well-written draft collects 8 failing findings
and scores NO_GO on copy that is fine. Every one of those findings tells the writer
to fix something they cannot fix yet, which is worse than silence: it buries the one
finding that was real.

Draft mode drops those findings, keeps everything a draft can actually answer, and
says in one advisory what was skipped and why.
"""

from __future__ import annotations

import pytest

from engine.draft import DRAFT_ADVISORY, calibrate_for_draft, looks_like_draft
from engine.parse import parse_eml
from engine.report import Report
from engine.runner import audit

_DRAFT = (
    b"From: Jane Okafor <jane@example.com>\r\n"
    b"To: reader@example.com\r\n"
    b"Subject: Your March water bill dropped 18 percent\r\n"
    b'Content-Type: multipart/alternative; boundary="b1"\r\n\r\n'
    b"--b1\r\nContent-Type: text/plain\r\n\r\n"
    b"Hi Sam,\r\n\r\nYour March water bill came in at 48 dollars, down from 59.\r\n"
    b"The new meter on Dundas Street caught a slow leak.\r\n\r\nJane\r\n"
    b"\r\n--b1\r\nContent-Type: text/html\r\n\r\n"
    b"<html><body><p>Hi Sam,</p><p>Your March water bill came in at 48 dollars, "
    b"down from 59. The new meter on Dundas Street caught a slow leak.</p>"
    b'<p><a href="https://example.com/r">Read it</a></p><p>Jane</p>'
    b'<p><a href="https://example.com/u">Unsubscribe</a></p></body></html>\r\n'
    b"\r\n--b1--\r\n"
)

_SENT = (
    b"Return-Path: <jane@example.com>\r\n"
    b"Received: from mail.example.com (mail.example.com [93.184.216.34])\r\n"
    b"\tby mx.google.com with ESMTPS id abc123; Tue, 29 Sep 2026 09:14:02 -0700\r\n"
    b"Authentication-Results: mx.google.com; spf=pass; dkim=pass; "
    b"dmarc=pass (p=REJECT)\r\n"
    b"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=s1; h=from:subject; "
    b"bh=abc=; b=def=\r\n"
    b"Message-ID: <abc@example.com>\r\n"
    b"Date: Tue, 29 Sep 2026 09:14:02 -0700\r\n" + _DRAFT
)


async def _audit(raw: bytes, *, draft: bool = False) -> Report:
    return await audit(parse_eml(raw), domain_health=False, draft=draft)


# ── detection ──────────────────────────────────────────────────────────────


def test_a_message_with_no_delivery_headers_looks_like_a_draft() -> None:
    assert looks_like_draft(parse_eml(_DRAFT)) is True


def test_a_delivered_message_does_not_look_like_a_draft() -> None:
    assert looks_like_draft(parse_eml(_SENT)) is False


def test_a_message_with_only_a_received_header_is_not_a_draft() -> None:
    # A Received header can only be added by a server that handled the message,
    # so its presence alone rules out "never sent".
    raw = b"Received: from a.example by b.example; Tue, 1 Sep 2026 10:00:00 +0000\r\n" + _DRAFT
    assert looks_like_draft(parse_eml(raw)) is False


def test_an_empty_message_is_not_claimed_as_a_draft() -> None:
    # Nothing to grade is not the same as a draft, and claiming otherwise would
    # make the advisory appear on junk input.
    assert looks_like_draft(parse_eml(b"")) is False


# ── what draft mode drops ──────────────────────────────────────────────────


async def test_a_good_draft_is_not_graded_as_a_failure() -> None:
    plain = await _audit(_DRAFT)
    as_draft = await _audit(_DRAFT, draft=True)
    assert as_draft.score > plain.score, (
        f"draft mode scored {as_draft.score}, plain scored {plain.score}; "
        "the delivery-header findings are still counting"
    )


async def test_the_hard_gate_for_alignment_is_cleared_in_draft_mode() -> None:
    # A draft cannot align anything, because nothing signed it. Leaving the gate
    # in place caps the score no matter how good the copy is.
    assert "auth.dmarc_alignment_overall" in (await _audit(_DRAFT)).hard_gates_failed
    assert (await _audit(_DRAFT, draft=True)).hard_gates_failed == []


@pytest.mark.parametrize(
    "check",
    [
        "auth.authentication_results",
        "auth.dmarc_alignment_dkim",
        "auth.dmarc_alignment_spf",
        "auth.dmarc_alignment_overall",
        "auth.tls_transport",
        "headers.date_sanity",
        "headers.message_id",
    ],
)
async def test_a_delivery_only_check_is_absent_in_draft_mode(check: str) -> None:
    report = await _audit(_DRAFT, draft=True)
    assert check not in {f.check for f in report.findings}


# ── what draft mode keeps ──────────────────────────────────────────────────


async def test_the_real_copy_finding_survives() -> None:
    # The whole point. A draft with no preview text has a problem the writer can
    # fix right now, and it was buried under 8 findings they could not.
    report = await _audit(_DRAFT, draft=True)
    failing = [f for f in report.findings if not f.passed]
    assert any(f.check == "copywriting.preheader_quality" for f in failing)


async def test_a_missing_subject_is_still_reported_in_draft_mode() -> None:
    # Date and Message-ID are added by the sending server. From, To, and Subject
    # are the writer's, so dropping the whole required-headers check would lose a
    # real defect.
    raw = _DRAFT.replace(b"Subject: Your March water bill dropped 18 percent\r\n", b"")
    report = await _audit(raw, draft=True)
    required = [f for f in report.findings if f.check == "headers.required_headers"]
    assert required, "the required-headers check must still run on a draft"
    assert required[0].passed is False
    assert "subject" in required[0].message.lower()


async def test_required_headers_passes_a_draft_missing_only_sent_headers() -> None:
    report = await _audit(_DRAFT, draft=True)
    required = [f for f in report.findings if f.check == "headers.required_headers"]
    assert required
    assert required[0].passed is True, required[0].message


async def test_copy_checks_run_normally_in_draft_mode() -> None:
    report = await _audit(_DRAFT, draft=True)
    copy_checks = [f for f in report.findings if f.check.startswith("copywriting.")]
    assert len(copy_checks) > 20, "draft mode must not reduce the copy audit"


# ── the advisory ───────────────────────────────────────────────────────────


async def test_draft_mode_says_what_it_skipped(x: None = None) -> None:
    report = await _audit(_DRAFT, draft=True)
    advisory = [f for f in report.findings if f.check == DRAFT_ADVISORY]
    assert advisory, "a report that silently skipped a third of the checks is misleading"
    message = advisory[0].message.lower()
    assert "draft" in message
    # It must say how to get the full picture, not only that something is missing.
    assert "send" in message


async def test_the_advisory_does_not_lower_the_score() -> None:
    report = await _audit(_DRAFT, draft=True)
    advisory = next(f for f in report.findings if f.check == DRAFT_ADVISORY)
    assert advisory.severity == "INFO"


# ── the hint when draft mode was not asked for ─────────────────────────────


async def test_a_draft_graded_without_the_flag_is_told_the_flag_exists() -> None:
    # The score is not changed silently. The caller is told that this looks unsent
    # and that there is a mode which grades it fairly.
    report = await _audit(_DRAFT)
    hint = [f for f in report.findings if f.check == "sender.looks_like_draft"]
    assert hint, "a draft graded as a send must say so"
    assert hint[0].severity == "INFO"
    assert hint[0].passed is True


async def test_a_delivered_message_gets_no_draft_hint() -> None:
    report = await _audit(_SENT)
    assert not [f for f in report.findings if f.check == "sender.looks_like_draft"]


async def test_draft_mode_does_not_add_the_hint_as_well() -> None:
    # Both at once would read as a contradiction: "this looks like a draft, pass
    # --draft" next to "draft mode is on".
    report = await _audit(_DRAFT, draft=True)
    assert not [f for f in report.findings if f.check == "sender.looks_like_draft"]


# ── draft mode on a delivered message ──────────────────────────────────────


async def test_draft_mode_on_a_delivered_message_still_drops_auth_findings() -> None:
    # The flag is the caller's claim about what they handed over. It must behave
    # the same either way rather than second-guessing them.
    report = await _audit(_SENT, draft=True)
    assert "auth.dmarc_alignment_overall" not in {f.check for f in report.findings}


# ── the calibration in isolation ───────────────────────────────────────────


def test_calibrating_an_empty_finding_list_returns_only_the_advisory() -> None:
    out = calibrate_for_draft([])
    assert len(out) == 1
    assert out[0].check == DRAFT_ADVISORY


async def test_the_advisory_names_the_sub_scores_it_did_not_verify() -> None:
    # A skipped category still scores 100, because the score is computed from an
    # absence of findings. Presenting that as "authentication is fine" would be
    # false, so the advisory has to name which numbers are not a verification.
    report = await _audit(_DRAFT, draft=True)
    advisory = next(f for f in report.findings if f.check == DRAFT_ADVISORY)
    assert report.sub_scores["authentication"] == 100
    assert advisory.details["unverified_sub_scores"] == ["authentication", "hygiene"]
    assert "not a verified result" in advisory.message


async def test_the_advisory_lists_what_it_skipped() -> None:
    report = await _audit(_DRAFT, draft=True)
    advisory = next(f for f in report.findings if f.check == DRAFT_ADVISORY)
    skipped = advisory.details["skipped_checks"]
    assert "auth.dmarc_alignment_overall" in skipped
    assert "auth.tls_transport" in skipped
