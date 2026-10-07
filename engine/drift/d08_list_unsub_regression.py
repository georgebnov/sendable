"""D08 — List-Unsubscribe compliance regression.

Fires when a sender loses their RFC 8058 one-click posture compared to
recent history. Relevant 2024/2025 rule: Gmail/Yahoo bulk senders lose
deliverability when the one-click handshake disappears.
"""

from __future__ import annotations

from engine.parse import ParsedEmail
from engine.report import Finding
from engine.severity import Severity
from engine.history import cold_start_ok

CHECK = "drift.d08_list_unsub_regression"


def _insufficient() -> Finding:
    return Finding(check=CHECK, severity=Severity.INFO, passed=True,
                   message="insufficient history for drift analysis")


async def run(email: ParsedEmail, current: dict, history: list[dict]) -> list[Finding]:
    if not cold_start_ok(history):
        return [_insufficient()]
    last10 = history[:10]
    if not last10:
        return [_insufficient()]
    n = len(last10)

    def _rate(field: str, val: int = 1) -> float:
        return sum(1 for r in last10 if r.get(field) == val) / n

    cur_mailto = current.get("list_unsub_has_mailto")
    cur_https = current.get("list_unsub_has_https")
    cur_oneclick = current.get("list_unsub_has_oneclick_post")
    cur_present = cur_mailto is not None or cur_https is not None

    present_rate = sum(
        1 for r in last10
        if r.get("list_unsub_has_mailto") is not None or r.get("list_unsub_has_https") is not None
    ) / n

    if present_rate >= 0.8 and not cur_present:
        return [Finding(
            check=CHECK,
            severity=Severity.HIGH,
            passed=False,
            message=(
                f"List-Unsubscribe header absent; history had it in "
                f"{present_rate:.0%} of last 10 sends."
            ),
            details={"history_present_rate": present_rate},
        )]

    oneclick_rate = _rate("list_unsub_has_oneclick_post")
    if oneclick_rate >= 0.8 and cur_oneclick != 1:
        return [Finding(
            check=CHECK,
            severity=Severity.HIGH,
            passed=False,
            message=(
                f"RFC 8058 one-click compliance lost: history "
                f"{oneclick_rate:.0%} of last 10 had List-Unsubscribe-Post=One-Click, "
                f"current is missing."
            ),
            details={"history_oneclick_rate": oneclick_rate, "current": cur_oneclick},
        )]

    https_rate = _rate("list_unsub_has_https")
    if https_rate >= 0.8 and cur_https != 1 and cur_mailto == 1:
        return [Finding(
            check=CHECK,
            severity=Severity.MEDIUM,
            passed=False,
            message=(
                f"Lost HTTPS unsubscribe URL; history {https_rate:.0%} of last 10 "
                f"had one, current is mailto-only."
            ),
            details={"history_https_rate": https_rate},
        )]

    return [Finding(
        check=CHECK,
        severity=Severity.INFO,
        passed=True,
        message="List-Unsubscribe compliance stable.",
    )]
