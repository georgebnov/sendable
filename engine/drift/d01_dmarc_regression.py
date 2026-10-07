"""D01 — DMARC alignment regression.

Fires when a sender whose history shows consistent DMARC pass produces a
message with DMARC fail/softfail. CRITICAL severity because 2024/2025
Gmail/Yahoo/Microsoft rules bulk-reject on DMARC fail.
"""

from __future__ import annotations

from engine.parse import ParsedEmail
from engine.report import Finding
from engine.severity import Severity
from engine.history import cold_start_ok

CHECK = "drift.d01_dmarc_regression"


def _insufficient() -> Finding:
    return Finding(check=CHECK, severity=Severity.INFO, passed=True,
                   message="insufficient history for drift analysis")


async def run(email: ParsedEmail, current: dict, history: list[dict]) -> list[Finding]:
    if not cold_start_ok(history):
        return [_insufficient()]

    cur = current.get("dmarc_result")
    if cur not in ("fail", "softfail"):
        return [Finding(check=CHECK, severity=Severity.INFO, passed=True,
                        message=f"DMARC={cur or 'missing'} (no regression).")]

    last_n = history[:10]
    prior = [r.get("dmarc_result") for r in last_n if r.get("dmarc_result")]
    n = len(prior)
    all_pass = n >= 3 and all(r == "pass" for r in prior)

    if all_pass:
        return [Finding(
            check=CHECK,
            severity=Severity.CRITICAL,
            passed=False,
            message=(
                f"DMARC regressed from {n}-of-{n} pass to '{cur}'. "
                f"2024/2025 bulk-sender rules reject on DMARC fail."
            ),
            details={"current": cur, "prior_results": prior},
        )]
    return [Finding(
        check=CHECK,
        severity=Severity.HIGH,
        passed=False,
        message=f"DMARC={cur}; history mixed or sparse, still a deliverability risk.",
        details={"current": cur, "prior_results": prior},
    )]
