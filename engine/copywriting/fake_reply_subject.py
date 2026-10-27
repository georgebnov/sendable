"""Fake Re:/Fwd: subject-prefix detection.

Bulk senders sometimes prefix subjects with "Re:" or "Fwd:" to mimic
the visual signature of a one-to-one reply and bait the recipient into
opening. This is:

  1. A CAN-SPAM §5(a)(2) violation (deceptive subject line) — federal
     liability regardless of filter behaviour.
  2. A direct spam-filter signal — Gmail and Outlook score subject-line
     thread cues against the presence of `In-Reply-To` / `References`
     headers and flag the mismatch.

Genuine replies/forwards from any MUA include `In-Reply-To` (RFC 5322
§3.6.4) referencing the prior message's `Message-ID`, plus a
`References` chain. Bulk-sender ESPs almost never inject these because
each campaign send is its own thread root.

Rule: if Subject starts with `Re:` / `Fwd:` / `Fw:` and NEITHER
`In-Reply-To` nor `References` is present, flag HIGH. Hard-gate the
finding — deceptive subject is a categorical disqualifier, not
something to weigh against other factors.
"""

from __future__ import annotations

import re

from ..parse import ParsedEmail
from ..report import Finding
from ..severity import Severity

_REPLY_PREFIX_RX = re.compile(
    r"^\s*(re|fwd|fw)\s*:",
    re.IGNORECASE,
)


def _has_thread_headers(email: ParsedEmail) -> tuple[bool, list[str]]:
    present: list[str] = []
    for h in ("in-reply-to", "references"):
        vals = email.headers.get(h) or []
        if any(v and v.strip() for v in vals):
            present.append(h)
    return bool(present), present


async def run(email: ParsedEmail) -> list[Finding]:
    subj = (email.subject or "").strip()
    if not subj:
        return [
            Finding(
                check="copywriting.fake_reply_subject",
                severity=Severity.INFO,
                passed=True,
                message="No subject to inspect for Re:/Fwd: prefix.",
                details={},
            )
        ]

    m = _REPLY_PREFIX_RX.match(subj)
    if not m:
        return [
            Finding(
                check="copywriting.fake_reply_subject",
                severity=Severity.INFO,
                passed=True,
                message="No Re:/Fwd: prefix on subject.",
                details={"subject": subj},
            )
        ]

    has_thread, present = _has_thread_headers(email)
    prefix = m.group(1).lower()

    if has_thread:
        return [
            Finding(
                check="copywriting.fake_reply_subject",
                severity=Severity.INFO,
                passed=True,
                message=(
                    f'Subject opens with "{prefix.title()}:" and thread '
                    f"headers are present ({', '.join(present)}): genuine "
                    f"reply/forward."
                ),
                details={
                    "prefix": prefix,
                    "thread_headers_present": present,
                    "subject": subj,
                },
            )
        ]

    return [
        Finding(
            check="copywriting.fake_reply_subject",
            severity=Severity.HIGH,
            passed=False,
            hard_gate=True,
            message=(
                f'The subject starts with "{prefix.title()}:" but this message '
                f"replies to nothing. The reply mark is false. Remove it. Gmail "
                f"and Outlook both score a false reply mark as spam. A subject "
                f"that misleads the reader is also illegal for commercial mail "
                f"in the United States."
            ),
            details={
                "prefix": prefix,
                "subject": subj,
                "in_reply_to_present": False,
                "references_present": False,
            },
        )
    ]
