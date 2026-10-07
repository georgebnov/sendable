"""Observability headers: Feedback-ID presence on bulk mail.

Gmail does not send ARF reports for privacy reasons. Senders add
`Feedback-ID: SenderID:campaign:customer:mailstream` so complaints are
attributed back to them via Gmail Postmaster Tools. Missing the header
on bulk mail means reputation can decay without visibility. Not a
delivery issue → INFO severity only.
"""

from __future__ import annotations

from ...parse import ParsedEmail
from ...report import Finding
from ...severity import Severity

_BULK_HEADERS = (
    "list-id",
    "feedback-id",
    "x-mailchimp-campaign-id",
    "x-campaign",
    "x-campaign-id",
    "x-klaviyo-messageid",
    "x-ac-campaign-id",
)


def _is_bulk(email: ParsedEmail) -> bool:
    for h in _BULK_HEADERS:
        if email.headers.get(h):
            return True
    precedence = email.headers.get("precedence", [])
    return bool(any(v.strip().lower() == "bulk" for v in precedence))


async def run(email: ParsedEmail) -> list[Finding]:
    fb = email.headers.get("feedback-id", [])
    if fb:
        return [
            Finding(
                check="headers.feedback_id",
                severity=Severity.INFO,
                passed=True,
                message="Feedback-ID present (Postmaster Tools visibility).",
                details={"value": fb[0][:120]},
            )
        ]

    if not _is_bulk(email):
        return []  # 1:1 mail doesn't need Feedback-ID; emit nothing.

    return [
        Finding(
            check="headers.feedback_id",
            severity=Severity.INFO,
            passed=False,
            message=(
                "Bulk mail without Feedback-ID header. Complaint attribution via "
                "Gmail Postmaster Tools depends on this; reputation regressions "
                "will be silent otherwise."
            ),
        )
    ]
