"""D03 — SPF / DKIM pass-to-fail flip.

If the sender's last 10 messages had ≥90% pass rate for SPF (or DKIM) and
the current message fails, flag HIGH. Both flipping at once → CRITICAL.
"""

from __future__ import annotations

from engine.parse import ParsedEmail
from engine.report import Finding
from engine.severity import Severity
from engine.history import cold_start_ok

CHECK = "drift.d03_auth_flip"


def _insufficient() -> Finding:
    return Finding(check=CHECK, severity=Severity.INFO, passed=True,
                   message="insufficient history for drift analysis")


async def run(email: ParsedEmail, current: dict, history: list[dict]) -> list[Finding]:
    if not cold_start_ok(history):
        return [_insufficient()]

    last10 = history[:10]
    n = max(1, len(last10))
    spf_rate = sum(1 for r in last10 if r.get("spf_result") == "pass") / n
    dkim_rate = sum(1 for r in last10 if r.get("dkim_result") == "pass") / n

    cur_spf = current.get("spf_result")
    cur_dkim = current.get("dkim_result")

    spf_bad = cur_spf in ("fail", "softfail")
    dkim_bad = cur_dkim in ("fail", "neutral")
    spf_flipped = spf_rate >= 0.9 and spf_bad
    dkim_flipped = dkim_rate >= 0.9 and dkim_bad

    if spf_flipped and dkim_flipped:
        return [Finding(
            check=CHECK,
            severity=Severity.CRITICAL,
            passed=False,
            message=(
                f"SPF and DKIM both regressed from ≥90% pass. "
                f"Current SPF={cur_spf}, DKIM={cur_dkim}."
            ),
            details={"spf_rate": spf_rate, "dkim_rate": dkim_rate,
                     "current_spf": cur_spf, "current_dkim": cur_dkim},
        )]
    if spf_flipped:
        return [Finding(
            check=CHECK,
            severity=Severity.HIGH,
            passed=False,
            message=f"SPF regressed: history pass-rate {spf_rate:.0%}, current={cur_spf}.",
            details={"spf_rate": spf_rate, "current_spf": cur_spf},
        )]
    if dkim_flipped:
        return [Finding(
            check=CHECK,
            severity=Severity.HIGH,
            passed=False,
            message=f"DKIM regressed: history pass-rate {dkim_rate:.0%}, current={cur_dkim}.",
            details={"dkim_rate": dkim_rate, "current_dkim": cur_dkim},
        )]
    return [Finding(
        check=CHECK,
        severity=Severity.INFO,
        passed=True,
        message=f"SPF/DKIM stable (SPF={cur_spf}, DKIM={cur_dkim}).",
    )]
