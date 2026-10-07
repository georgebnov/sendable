"""Parse Microsoft EOP (Exchange Online Protection) verdict headers.

When a message transits a Microsoft 365 / Outlook.com mailbox, EOP
stamps two diagnostic headers that tell us *exactly* what Microsoft
thought of the send — no guessing required.

  - `X-Forefront-Antispam-Report` carries `SCL:n SFV:CODE CIP:ip ...`
  - `X-Microsoft-Antispam` carries `BCL:n` (and other auxiliary fields)
  - `Authentication-Results` may carry `compauth=fail reason=...`
    (composite authentication: Microsoft's blended SPF+DKIM+DMARC verdict)

We surface these as findings so the user sees Microsoft's classification
without us re-deriving it from content. Useful when the mailbox is
M365 / Outlook.com — silently no-ops on Gmail-only paths.

Severity mapping follows Microsoft's own SCL/BCL semantics
(learn.microsoft.com/.../anti-spam-message-headers):

  SCL: -1/0/1 → INFO pass · 5/6 → MEDIUM · 7/8/9 → HIGH (high-confidence spam)
  BCL: 0–3 → INFO · 4–7 → LOW · 8–9 → MEDIUM (essentially spam)
  compauth=pass → INFO · softpass/none → LOW · fail → HIGH

Doc tier: §8 (Microsoft-specific systems).
"""

from __future__ import annotations

import re

from ...parse import ParsedEmail
from ...report import Finding
from ...severity import Severity

CHECK_PREFIX = "microsoft_eop"

_SCL_RX = re.compile(r"\bSCL\s*:\s*(-?\d+)", re.IGNORECASE)
_SFV_RX = re.compile(r"\bSFV\s*:\s*([A-Z]+)", re.IGNORECASE)
_BCL_RX = re.compile(r"\bBCL\s*:\s*(\d+)", re.IGNORECASE)
_COMPAUTH_RX = re.compile(r"\bcompauth\s*=\s*([a-z]+)(?:\s+reason\s*=\s*(\d+))?", re.IGNORECASE)

# SFV codes from Microsoft docs — what they mean for the message disposition.
_SFV_MEANINGS = {
    "NSPM": ("not spam", Severity.INFO, True),
    "SPM": ("content-filter spam", Severity.HIGH, False),
    "SKN": ("skipped (allowed by Mail-Flow rule)", Severity.INFO, True),
    "SKS": ("skipped (allowed by spam-filter policy)", Severity.INFO, True),
    "SKA": ("skipped (Safe Sender / IP Allow list)", Severity.INFO, True),
    "SKB": ("blocked (sender on block list)", Severity.HIGH, False),
    "SKI": ("skipped (other reason)", Severity.INFO, True),
    "SKQ": ("released from quarantine", Severity.INFO, True),
    "SFE": ("Outlook Safe Sender list bypass", Severity.INFO, True),
    "BLK": ("Outlook Blocked Sender", Severity.HIGH, False),
    "PHSH": ("phishing", Severity.CRITICAL, False),
    "AAD": ("Azure AD authentication phish", Severity.CRITICAL, False),
}

_COMPAUTH_SEVERITIES = {
    "pass": (Severity.INFO, True, "Composite authentication passed."),
    "softpass": (
        Severity.LOW,
        False,
        "Composite authentication soft-pass (not all signals clean).",
    ),
    "none": (Severity.LOW, False, "No composite authentication available."),
    "fail": (
        Severity.HIGH,
        False,
        "Composite authentication FAILED — Microsoft does not trust the sender's auth combo.",
    ),
}


def _scl_severity(scl: int) -> tuple[Severity, bool, str]:
    if scl < 0:
        return (
            Severity.INFO,
            True,
            f"SCL={scl} (filtering bypassed; Safe Sender / mail-flow rule).",
        )
    if scl in (0, 1):
        return (Severity.INFO, True, f"SCL={scl} (Microsoft classified: not spam).")
    if scl in (5, 6):
        return (
            Severity.MEDIUM,
            False,
            f"SCL={scl} (Microsoft classified: spam → Junk by default).",
        )
    if scl in (7, 8, 9):
        return (
            Severity.HIGH,
            False,
            f"SCL={scl} (Microsoft classified: high-confidence spam → Quarantine on "
            f"Standard/Strict).",
        )
    return (Severity.LOW, False, f"SCL={scl} (unrecognized value).")


def _bcl_severity(bcl: int) -> tuple[Severity, bool, str]:
    if bcl <= 3:
        return (Severity.INFO, True, f"BCL={bcl} (not bulk, or low-complaint bulk).")
    if bcl <= 7:
        return (
            Severity.LOW,
            False,
            f"BCL={bcl} (medium-complaint bulk; default policy threshold = 7).",
        )
    return (Severity.MEDIUM, False, f"BCL={bcl} (high-complaint bulk — essentially spam).")


async def run(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    headers = email.headers

    forefront = headers.get("x-forefront-antispam-report", [])
    antispam = headers.get("x-microsoft-antispam", [])
    auth_results = headers.get("authentication-results", [])

    saw_microsoft = bool(
        forefront or antispam or any("microsoft.com" in ar.lower() for ar in auth_results)
    )
    if not saw_microsoft:
        return [
            Finding(
                check=f"{CHECK_PREFIX}.transit",
                severity=Severity.INFO,
                passed=True,
                message="No Microsoft EOP headers — message did not transit M365/Outlook.",
            )
        ]

    findings.append(
        Finding(
            check=f"{CHECK_PREFIX}.transit",
            severity=Severity.INFO,
            passed=True,
            message="Microsoft EOP transit detected; parsing verdict headers.",
        )
    )

    # ─── SCL ─────────────────────────────────────────────────────────
    if forefront:
        joined = " ".join(forefront)
        m = _SCL_RX.search(joined)
        if m:
            try:
                scl = int(m.group(1))
                sev, passed, msg = _scl_severity(scl)
                findings.append(
                    Finding(
                        check=f"{CHECK_PREFIX}.scl",
                        severity=sev,
                        passed=passed,
                        message=msg,
                        details={"scl": scl},
                    )
                )
            except ValueError:
                pass

        # ─── SFV (filter result code) ────────────────────────────────
        sfv = _SFV_RX.search(joined)
        if sfv:
            code = sfv.group(1).upper()
            meaning, sev, passed = _SFV_MEANINGS.get(
                code, (f"unknown SFV code '{code}'", Severity.LOW, False)
            )
            findings.append(
                Finding(
                    check=f"{CHECK_PREFIX}.sfv",
                    severity=sev,
                    passed=passed,
                    message=f"Microsoft SFV={code} — {meaning}.",
                    details={"sfv": code, "meaning": meaning},
                )
            )

    # ─── BCL ─────────────────────────────────────────────────────────
    if antispam:
        joined = " ".join(antispam)
        m = _BCL_RX.search(joined)
        if m:
            try:
                bcl = int(m.group(1))
                sev, passed, msg = _bcl_severity(bcl)
                findings.append(
                    Finding(
                        check=f"{CHECK_PREFIX}.bcl",
                        severity=sev,
                        passed=passed,
                        message=msg,
                        details={"bcl": bcl},
                    )
                )
            except ValueError:
                pass

    # ─── compauth ────────────────────────────────────────────────────
    for ar in auth_results:
        m = _COMPAUTH_RX.search(ar)
        if not m:
            continue
        verdict = m.group(1).lower()
        reason = m.group(2)
        sev, passed, base_msg = _COMPAUTH_SEVERITIES.get(
            verdict,
            (Severity.LOW, False, f"compauth={verdict} (unrecognized verdict)."),
        )
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.compauth",
                severity=sev,
                passed=passed,
                message=f"{base_msg}{f' Reason code: {reason}.' if reason else ''}",
                details={"compauth": verdict, "reason": reason},
            )
        )
        break  # one verdict per message — first wins

    return findings
