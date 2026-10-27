"""Parse Authentication-Results header(s). Never re-verify DKIM.

We report what the receiving MTA said. Re-verifying would fail on forwarded
mail because the body hash changes — false failures we don't want.

DMARC verdict policy (matters for accuracy):
  - The dmarc= token is the receiver's QUICK-VIEW result. Many receivers
    omit it or apply a strict-SPF heuristic that disagrees with the actual
    DMARC algorithm. Treating "no dmarc= token" as a hard failure
    misclassifies a huge swath of legitimate traffic (especially ESP-sent
    mail with bounce subdomains).
  - The AUTHORITATIVE verdict for our tool comes from
    `auth.dmarc_alignment_overall` in alignment.py — that one applies
    the actual algorithm (PASS if EITHER aligned-SPF passes OR
    aligned-DKIM passes) against From / d= / Return-Path.
  - This module reports the raw AR tokens as INFO-level signals; missing
    tokens are surfaced as INFO ("no quick-view verdict in headers"), not
    HIGH. When a token contradicts our computed alignment, we say so but
    do not raise it to CRITICAL.
"""

from __future__ import annotations

import re

from ...parse import ParsedEmail
from ...report import Finding
from ...severity import Severity

_METHOD_RE = re.compile(r"\b(spf|dkim|dmarc|arc|bimi)\s*=\s*([a-zA-Z]+)")
_DMARC_POLICY_RE = re.compile(r"\bp\s*=\s*([a-zA-Z]+)", re.IGNORECASE)


async def run(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    ar = email.authentication_results
    if not ar:
        findings.append(
            Finding(
                check="auth.authentication_results",
                severity=Severity.HIGH,
                passed=False,
                message=(
                    "No Authentication-Results header; receiver did not "
                    "authenticate (or it was stripped)."
                ),
            )
        )
        return findings

    joined = " ".join(ar)
    results: dict[str, str] = {}
    for m in _METHOD_RE.finditer(joined):
        method, result = m.group(1).lower(), m.group(2).lower()
        results.setdefault(method, result)

    for method in ("spf", "dkim", "dmarc"):
        result = results.get(method)
        passed = result == "pass"

        if method == "dmarc":
            # Missing dmarc= token is NOT a failure — many receivers omit it,
            # and our authoritative verdict comes from auth.dmarc_alignment_overall.
            # A receiver-reported dmarc=fail is interesting but never CRITICAL
            # by itself; alignment.py is the source of truth.
            if result is None:
                sev = Severity.INFO
                msg = (
                    "No DMARC verdict in receiver headers. See "
                    "auth.dmarc_alignment_overall for the computed result."
                )
                # Reported as passed=True so this missing-token case stops
                # dragging the auth subscore down. The real verdict, pass
                # or fail, lives in alignment_overall.
                passed = True
            elif result in ("fail", "softfail"):
                # Receiver said fail. Surface it but at MEDIUM — alignment_overall
                # tells the user whether the actual algorithm agrees. Many
                # 'show original' UIs render fail when the strict-SPF heuristic
                # disagrees with the relaxed alignment we (correctly) compute.
                sev = Severity.MEDIUM
                msg = (
                    f"Receiver quick-view says DMARC={result}. Cross-check "
                    "auth.dmarc_alignment_overall: if alignment passes, the "
                    "message authenticates correctly under the actual "
                    "algorithm and this is a receiver-UI quirk."
                )
            else:
                sev = Severity.INFO
                msg = f"DMARC={result}"
        else:
            sev = Severity.INFO if passed else Severity.HIGH
            msg = f"{method.upper()}={result or 'missing'}"

        findings.append(
            Finding(
                check=f"auth.{method}",
                severity=sev,
                passed=passed,
                message=msg,
                details={"result": result},
            )
        )

    for extra in ("arc", "bimi"):
        if extra in results:
            findings.append(
                Finding(
                    check=f"auth.{extra}",
                    severity=Severity.INFO,
                    passed=results[extra] == "pass",
                    message=f"{extra.upper()}={results[extra]}",
                    details={"result": results[extra]},
                )
            )

    # DMARC policy strength. The receiver's Authentication-Results header
    # echoes the sender's published policy as `p=NONE|QUARANTINE|REJECT`.
    # `p=none` lets DMARC pass without enforcement, which most providers
    # weight lower for reputation. Surface as LOW so it's visible without
    # dominating the score.
    policy: str | None = None
    for m in _DMARC_POLICY_RE.finditer(joined):
        policy = m.group(1).lower()
        break
    if policy is not None:
        if policy == "none":
            findings.append(
                Finding(
                    check="auth.dmarc_policy_strength",
                    severity=Severity.LOW,
                    passed=False,
                    message=(
                        "DMARC policy is p=none (monitor-only). Providers weight "
                        "this lower for reputation; consider p=quarantine or "
                        "p=reject once authentication is stable."
                    ),
                    details={"policy": policy},
                    family="dmarc_policy",
                )
            )
        else:
            findings.append(
                Finding(
                    check="auth.dmarc_policy_strength",
                    severity=Severity.INFO,
                    passed=True,
                    message=f"DMARC policy is p={policy}.",
                    details={"policy": policy},
                )
            )

    return findings
