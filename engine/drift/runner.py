"""Drift runner — fans out Phase 1 drift checks via asyncio.gather.

Same shape as audit/runner.py's CHECKS list, but each check takes a
(email, current_derived, history) tuple rather than just the ParsedEmail.
`current_derived` is computed once here so the 6 checks don't each re-parse.
"""

from __future__ import annotations

import asyncio

from engine.derived import extract_all
from engine.drift import (
    d01_dmarc_regression,
    d03_auth_flip,
    d04_dmarc_policy_downgrade,
    d08_list_unsub_regression,
    d10_display_name_rotation,
    d11_reply_to_divergence,
)
from engine.history import EmailFacts
from engine.parse import ParsedEmail
from engine.report import Finding

DRIFT_CHECKS = [
    d01_dmarc_regression.run,
    d03_auth_flip.run,
    d04_dmarc_policy_downgrade.run,
    d08_list_unsub_regression.run,
    d10_display_name_rotation.run,
    d11_reply_to_divergence.run,
]


async def run_drift(email: ParsedEmail, history: list[EmailFacts]) -> list[Finding]:
    current = extract_all(email)
    results = await asyncio.gather(*(c(email, current, history) for c in DRIFT_CHECKS))
    return [f for sublist in results for f in sublist]
