"""D11 — Reply-To domain divergence from From, bulk mail only.

A new Reply-To domain that diverges from From, and that hasn't appeared
in the sender's prior history, is the classic scam / VEC pattern. Freemail
as the new Reply-To domain (on bulk mail) is especially strong signal.

Only runs when the email is bulk (reuses `audit/checks/unsubscribe._is_bulk`).
Personal 1:1 mail naturally has a varied Reply-To and shouldn't flag.
"""

from __future__ import annotations

from engine.domain.integrity.unsubscribe import _is_bulk
from engine.history import EmailFacts, cold_start_ok
from engine.parse import ParsedEmail
from engine.report import Finding
from engine.severity import Severity

CHECK = "drift.d11_reply_to_divergence"

_FREEMAIL = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "yahoo.com",
    "ymail.com",
    "proton.me",
    "protonmail.com",
    "icloud.com",
    "me.com",
    "yandex.com",
    "yandex.ru",
    "mail.ru",
    "aol.com",
}


def _insufficient(msg: str = "insufficient history for drift analysis") -> Finding:
    return Finding(check=CHECK, severity=Severity.INFO, passed=True, message=msg)


async def run(email: ParsedEmail, current: EmailFacts, history: list[EmailFacts]) -> list[Finding]:
    if not _is_bulk(email):
        return [
            Finding(
                check=CHECK,
                severity=Severity.INFO,
                passed=True,
                message="not bulk mail — Reply-To drift not evaluated",
            )
        ]

    if not cold_start_ok(history):
        return [_insufficient()]

    cur_reply = current.get("reply_to_domain")
    cur_from = current.get("from_domain")

    if not cur_reply or cur_reply == cur_from:
        return [
            Finding(
                check=CHECK,
                severity=Severity.INFO,
                passed=True,
                message="Reply-To aligned with From-domain.",
            )
        ]

    prior_rows = [r for r in history if r.get("reply_to_domain")]
    if len(prior_rows) < 3:
        return [_insufficient("Reply-To history too sparse for drift analysis")]
    prior = {domain for r in prior_rows if (domain := r.get("reply_to_domain"))}

    if cur_reply in prior:
        return [
            Finding(
                check=CHECK,
                severity=Severity.INFO,
                passed=True,
                message=f"Reply-To '{cur_reply}' seen in history.",
            )
        ]

    is_new_freemail = cur_reply in _FREEMAIL
    had_freemail_prior = any(p in _FREEMAIL for p in prior)

    if is_new_freemail and not had_freemail_prior:
        return [
            Finding(
                check=CHECK,
                severity=Severity.CRITICAL,
                passed=False,
                message=(
                    f"New Reply-To freemail domain '{cur_reply}' on bulk mail; "
                    f"canonical scam pattern (SpamAssassin FREEMAIL_FORGED_REPLYTO)."
                ),
                details={"current": cur_reply, "prior": sorted(prior)[:10]},
            )
        ]
    return [
        Finding(
            check=CHECK,
            severity=Severity.HIGH,
            passed=False,
            message=(
                f"New Reply-To domain '{cur_reply}' not in prior {len(prior)} "
                f"distinct values for this sender."
            ),
            details={"current": cur_reply, "prior": sorted(prior)[:10]},
        )
    ]
