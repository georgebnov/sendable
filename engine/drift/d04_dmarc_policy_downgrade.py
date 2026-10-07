"""D04 — DMARC policy downgrade observed.

Policies rank none=0 < quarantine=1 < reject=2. If the current message's
observed `p=` value is lower-ranked than the maximum seen in the sender's
last 30 days, flag HIGH — a policy regression indicates an ops incident
during an ESP onboarding (or, rarely, DNS compromise).

Upgrades (e.g. none → reject) get no finding in Phase 1. Positive-drift
handling is deferred to Phase 3.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from engine.parse import ParsedEmail
from engine.report import Finding
from engine.severity import Severity
from engine.history import cold_start_ok

CHECK = "drift.d04_dmarc_policy_downgrade"
_POLICY_RANK = {"none": 0, "quarantine": 1, "reject": 2}


def _insufficient(msg: str = "insufficient history for drift analysis") -> Finding:
    return Finding(check=CHECK, severity=Severity.INFO, passed=True, message=msg)


async def run(email: ParsedEmail, current: dict, history: list[dict]) -> list[Finding]:
    if not cold_start_ok(history):
        return [_insufficient()]

    cur_policy = current.get("dmarc_policy")
    if not cur_policy:
        return [_insufficient("DMARC policy comment absent in AR — cannot evaluate.")]
    cur_rank = _POLICY_RANK.get(cur_policy)
    if cur_rank is None:
        return [_insufficient(f"Unknown DMARC policy value: {cur_policy}")]

    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    window = []
    for r in history:
        try:
            rat = datetime.fromisoformat(r["received_at"])
            if rat.tzinfo is None:
                rat = rat.replace(tzinfo=timezone.utc)
            if rat >= cutoff:
                window.append(r)
        except Exception:
            continue

    policies = [r.get("dmarc_policy") for r in window if r.get("dmarc_policy")]
    if not policies:
        return [_insufficient("no DMARC policy history in last 30 days")]

    max_rank = max(_POLICY_RANK.get(p, -1) for p in policies)
    if cur_rank < max_rank:
        max_policy = next(p for p in policies if _POLICY_RANK.get(p, -1) == max_rank)
        return [Finding(
            check=CHECK,
            severity=Severity.HIGH,
            passed=False,
            message=(
                f"DMARC policy downgraded: historical max p={max_policy}, "
                f"current p={cur_policy}. Usually an ops/DNS incident."
            ),
            details={"current": cur_policy, "historical_max": max_policy},
        )]
    return [Finding(
        check=CHECK,
        severity=Severity.INFO,
        passed=True,
        message=f"DMARC policy p={cur_policy} consistent with or stronger than history.",
    )]
