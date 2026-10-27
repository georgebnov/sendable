"""Grading an email that has not been sent yet.

An agent writing an email has a draft. It does not have a delivered message, and a
large part of the audit reads headers that only exist after a message has been sent
and received:

  - `Authentication-Results`, which the receiving server writes. Every SPF, DKIM,
    and DMARC result comes from it.
  - `DKIM-Signature`, added by the sending server when it signs.
  - `Return-Path`, set by the sending server. SPF alignment is measured against it.
  - `Received`, added by each server that handles the message. Transport TLS is
    read from the last hop.
  - `Date` and `Message-ID`, which the sending server adds on submission.

Graded as if it were a real send, a well-written draft collects 8 failing findings
and a hard-gate failure, and scores NO_GO on copy that is fine. Every one of those
findings tells the writer to fix something they cannot fix yet. That is worse than
saying nothing, because it buries the finding that was real.

`calibrate_for_draft` drops those findings, keeps everything a draft can answer,
and appends one advisory saying what was skipped and how to get the rest.

Two rules kept this honest.

The mode is never entered on its own. `looks_like_draft` only produces a hint
finding telling the caller the mode exists. Silently changing how a message is
scored, based on a guess about what it is, would make two runs of the same tool
disagree for reasons the caller cannot see.

`headers.required_headers` is rewritten rather than dropped. It checks From, To,
Date, Subject, and Message-ID. Date and Message-ID belong to the sending server,
but the other three are the writer's, and a draft with no subject is a real defect
that dropping the whole check would hide.
"""

from __future__ import annotations

from .parse import ParsedEmail
from .report import Finding
from .severity import Severity

DRAFT_ADVISORY = "sender.draft_mode"
DRAFT_HINT = "sender.looks_like_draft"

# Checks that read a header only a server can add. Every one of these is
# unanswerable for a message that was never sent.
_DELIVERY_ONLY_CHECKS = frozenset(
    {
        # All of these are parsed out of Authentication-Results.
        "auth.authentication_results",
        "auth.spf",
        "auth.dkim",
        "auth.dmarc",
        "auth.dmarc_policy_strength",
        # Alignment needs a DKIM signature and a Return-Path.
        "auth.dmarc_alignment_dkim",
        "auth.dmarc_alignment_spf",
        "auth.dmarc_alignment_overall",
        # Transport TLS is read from the Received chain.
        "auth.tls_transport",
        # Date and Message-ID are added on submission.
        "headers.date_sanity",
        "headers.message_id",
        # Received-header ordering and timing.
        "headers.received_chain",
        "headers.date_drift",
    }
)

# Prefixes for whole families that only a receiving server produces.
_DELIVERY_ONLY_PREFIXES = (
    # Microsoft's spam-confidence headers are stamped by Exchange Online.
    "microsoft_eop.",
    # Drift compares authentication results across sends, and a draft has none.
    "drift.",
)

# The headers in `headers.required_headers` that a draft legitimately lacks,
# because the sending server adds them on submission.
_SERVER_ADDED_HEADERS = ("date", "message-id")


def looks_like_draft(email: ParsedEmail) -> bool:
    """True when the message carries no sign of ever having been sent.

    A `Received` header can only be added by a server that handled the message, and
    `Authentication-Results` only by a receiving one. Either present means the
    message was sent, whatever else is missing.

    A message with no From and no subject is not called a draft. Nothing to grade
    is a different thing, and claiming otherwise would put the advisory on junk.
    """
    if email.headers.get("received") or email.headers.get("authentication-results"):
        return False
    if email.headers.get("dkim-signature") or email.headers.get("return-path"):
        return False
    return bool(email.from_addr or email.subject)


def _rewrite_required_headers(finding: Finding) -> Finding | None:
    """Re-judge the required-header check for a draft.

    From, To, and Subject are the writer's and still count. Date and Message-ID
    are added on submission, so their absence is not a defect here.

    Returns the adjusted finding, or None when there is nothing left to report.
    """
    if finding.passed:
        # Already passing, so there is nothing a draft could have failed. The
        # passing finding carries no details["missing"], and treating that as an
        # unexpected shape deleted a check that had actually run and then reported
        # it as skipped, which is the opposite of what happened.
        return finding

    missing = finding.details.get("missing")
    if not isinstance(missing, list):
        # Failing, but not in the shape this knows how to re-judge. Dropping it is
        # safer than guessing, because the message would otherwise name headers a
        # draft cannot have.
        return None

    writer_missing = [h for h in missing if str(h).lower() not in _SERVER_ADDED_HEADERS]
    if not writer_missing:
        return Finding(
            check=finding.check,
            severity=Severity.INFO,
            passed=True,
            message=(
                "The message carries every header you control. Your sending tool "
                "adds the date and the message id when the message goes out."
            ),
            details={"missing_on_send": sorted(str(h) for h in missing)},
        )
    return Finding(
        check=finding.check,
        severity=finding.severity,
        passed=False,
        message=(
            f"Missing header(s) you need to set: {sorted(str(h) for h in writer_missing)}. "
            f"Filters treat a message without these as malformed."
        ),
        details={"missing": sorted(str(h) for h in writer_missing)},
        hard_gate=finding.hard_gate,
    )


def calibrate_for_draft(findings: list[Finding]) -> list[Finding]:
    """Drop the findings a draft cannot answer and explain what was skipped.

    Returns a new list. The findings passed in are not changed.
    """
    kept: list[Finding] = []
    skipped: list[str] = []

    for finding in findings:
        if finding.check == "headers.required_headers":
            rewritten = _rewrite_required_headers(finding)
            if rewritten is not None:
                kept.append(rewritten)
            else:
                skipped.append(finding.check)
            continue
        if finding.check in _DELIVERY_ONLY_CHECKS or finding.check.startswith(
            _DELIVERY_ONLY_PREFIXES
        ):
            skipped.append(finding.check)
            continue
        kept.append(finding)

    kept.append(
        Finding(
            check=DRAFT_ADVISORY,
            # INFO carries no score penalty. The advisory explains the report, it
            # is not a defect in the email.
            severity=Severity.INFO,
            passed=True,
            message=(
                "Graded as a draft. The audit skipped every check that needs a "
                "sent message. Those are your authentication results, the "
                "encryption in transit, and the headers your sending tool adds. "
                "Those depend on how the message is sent, not on what you wrote. "
                "Because they were skipped and not passed, the authentication and "
                "hygiene sub-scores show only what a draft can show. They are not "
                "a verified result. To check them, send this to yourself and audit "
                "the copy you receive."
            ),
            details={
                "skipped_checks": sorted(skipped),
                # Named so a caller does not present a skipped category as a
                # verified one. The score for these reflects an absence of
                # findings, not a passing result.
                "unverified_sub_scores": ["authentication", "hygiene"],
            },
        )
    )
    return kept


def draft_hint() -> Finding:
    """A note that this message looks unsent, and that a fairer mode exists.

    Deliberately a hint and not an automatic switch. Changing how a message is
    scored based on a guess would make two runs disagree for reasons the caller
    cannot see in the output.
    """
    return Finding(
        check=DRAFT_HINT,
        severity=Severity.INFO,
        passed=True,
        message=(
            "This message has no Received or Authentication-Results header, so it "
            "looks like a draft that was never sent. It was still graded as a real "
            "send, which is why the authentication checks fail: there is nothing "
            "for them to read. Re-run in draft mode to score only what a draft can "
            "show."
        ),
        details={"hint": "pass draft=True, or --draft on the command line"},
    )


__all__ = [
    "DRAFT_ADVISORY",
    "DRAFT_HINT",
    "calibrate_for_draft",
    "draft_hint",
    "looks_like_draft",
]
