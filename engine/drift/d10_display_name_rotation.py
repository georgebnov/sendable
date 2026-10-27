"""D10 — Display-name rotation on a stable From address.

Two concerns:
 (1) a never-before-seen display name on a sender that has a stable history
 (2) excessive churn in display names overall (shared-inbox abuse, rotating
     sales-rep "faces," reputation-evasion tooling)
Plus a zero-history special case: friendly-from spoofs where the display
name contains an address-like token or a brand string mismatched from the
sending domain (GreatHorn 91%-of-phishing pattern).
"""

from __future__ import annotations

import re

from engine.history import EmailFacts, cold_start_ok, rows_within
from engine.parse import ParsedEmail
from engine.report import Finding
from engine.severity import Severity

CHECK = "drift.d10_display_name_rotation"

# Address-like token detection inside display names.
_TLD_HINT_RX = re.compile(r"\.[a-z]{2,}\b", re.IGNORECASE)
# Small list of brand tokens commonly spoofed.
_KNOWN_BRANDS = {
    "paypal",
    "google",
    "microsoft",
    "apple",
    "amazon",
    "facebook",
    "linkedin",
    "instagram",
    "netflix",
    "dropbox",
    "ebay",
    "bank",
    "chase",
    "wellsfargo",
}


def _insufficient() -> Finding:
    return Finding(
        check=CHECK,
        severity=Severity.INFO,
        passed=True,
        message="insufficient history for drift analysis",
    )


async def run(email: ParsedEmail, current: EmailFacts, history: list[EmailFacts]) -> list[Finding]:
    cur_name = current.get("display_name")
    cur_domain = current.get("from_domain") or ""

    # Friendly-from spoof patterns (fire even with no history). Only flag the
    # address-in-display case when the embedded domain DIFFERS from from_domain
    # — Kit / ConvertKit legitimately put `"info@brand.com" <info@brand.com>`
    # as the From, and that's not a spoof.
    if cur_name:
        if "@" in cur_name:
            # Extract whatever looks like a domain out of the display name and
            # compare to from_domain.
            embedded_domain = cur_name.rsplit("@", 1)[-1].strip().strip("<>,. ").lower()
            # Loose containment check handles ESP subdomains vs brand domain.
            if (
                embedded_domain
                and cur_domain
                and embedded_domain != cur_domain
                and cur_domain not in embedded_domain
                and embedded_domain not in cur_domain
            ):
                return [
                    Finding(
                        check=CHECK,
                        severity=Severity.HIGH,
                        passed=False,
                        message=(
                            f"Display-name email '{cur_name}' points at '{embedded_domain}' "
                            f"but From domain is '{cur_domain}'; friendly-from spoof pattern."
                        ),
                        details={
                            "display_name": cur_name,
                            "embedded_domain": embedded_domain,
                            "from_domain": cur_domain,
                        },
                    )
                ]
        elif _TLD_HINT_RX.search(cur_name):
            # A TLD-like token in the display name with no @ sign — flag as
            # potential spoof unless the token is a substring of from_domain.
            if cur_domain not in cur_name:
                return [
                    Finding(
                        check=CHECK,
                        severity=Severity.HIGH,
                        passed=False,
                        message=(
                            f"Display name '{cur_name}' contains a TLD-like token "
                            f"unrelated to From domain '{cur_domain}'; friendly-from spoof pattern."
                        ),
                        details={"display_name": cur_name, "from_domain": cur_domain},
                    )
                ]
        for brand in _KNOWN_BRANDS:
            if brand in cur_name and brand not in cur_domain:
                return [
                    Finding(
                        check=CHECK,
                        severity=Severity.HIGH,
                        passed=False,
                        message=(
                            f"Display name mentions '{brand}' but domain is "
                            f"'{cur_domain}'; friendly-from abuse pattern."
                        ),
                        details={
                            "display_name": cur_name,
                            "from_domain": cur_domain,
                            "brand": brand,
                        },
                    )
                ]

    # Rotation check needs ≥8 historical rows per research.
    if not cold_start_ok(history, min_rows=8):
        return [_insufficient()]

    window = rows_within(history, days=90)

    names = {name for r in window if (name := r.get("display_name"))}
    if not cur_name or not names:
        return [
            Finding(
                check=CHECK,
                severity=Severity.INFO,
                passed=True,
                message="no display-name baseline yet",
            )
        ]

    n_distinct = len(names)
    n_rows = len(window)
    is_new = cur_name not in names
    churn_ratio = n_distinct / n_rows if n_rows else 0

    findings: list[Finding] = []
    if is_new and n_distinct >= 3:
        findings.append(
            Finding(
                check=CHECK,
                severity=Severity.MEDIUM,
                passed=False,
                message=(
                    f"New display name '{cur_name}' not seen in last {n_rows} sends "
                    f"(sender has used {n_distinct} distinct names in 90-day window)."
                ),
                details={
                    "new_name": cur_name,
                    "history": sorted(names)[:10],
                    "distinct_count": n_distinct,
                    "rows": n_rows,
                },
            )
        )
    if churn_ratio > 0.5:
        findings.append(
            Finding(
                check=CHECK,
                severity=Severity.HIGH,
                passed=False,
                message=(
                    f"Display-name churn {churn_ratio:.0%}: {n_distinct} distinct names "
                    f"across {n_rows} sends: excessive rotation."
                ),
                details={"churn_ratio": churn_ratio, "distinct_count": n_distinct, "rows": n_rows},
            )
        )
    elif churn_ratio > 0.3:
        findings.append(
            Finding(
                check=CHECK,
                severity=Severity.MEDIUM,
                passed=False,
                message=(
                    f"Display-name churn {churn_ratio:.0%}: {n_distinct} distinct names "
                    f"across {n_rows} sends."
                ),
                details={"churn_ratio": churn_ratio, "distinct_count": n_distinct, "rows": n_rows},
            )
        )

    if not findings:
        return [
            Finding(
                check=CHECK,
                severity=Severity.INFO,
                passed=True,
                message=(
                    f"Display-name stable ('{cur_name}'; "
                    f"{n_distinct} distinct / {n_rows} rows, churn {churn_ratio:.0%})."
                ),
            )
        ]
    return findings
