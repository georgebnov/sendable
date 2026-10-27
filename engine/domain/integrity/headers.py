"""RFC 5322 header floor: required headers, no duplicates, sane Date,
well-formed Message-ID.

These are SpamAssassin-tier rules that filters score even when reputation
is fine. Each individual rule is small (<= 1.5 SA points) but they
compound — a campaign missing Message-ID + Date + with two From headers
adds ~4 points before any content scoring runs. Cheap to fix, cheap to
catch.

Doc tier: §9 (header / MIME structure signals).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

from ...parse import ParsedEmail
from ...report import Finding
from ...severity import Severity

CHECK_PREFIX = "headers"

_REQUIRED_HEADERS = ("from", "to", "date", "subject", "message-id")
_NO_DUPLICATE_HEADERS = ("from", "to", "subject", "date", "message-id", "reply-to")
_DATE_DRIFT_DAYS = 7

# RFC 5322 Message-ID is `<id-left@id-right>`. Lenient bracket form
# accepted — some senders strip brackets but Gmail/Outlook still file.
_MSG_ID_RX = re.compile(r"^\s*<?[^@<>\s]+@[^@<>\s]+>?\s*$")


def _parse_received_date(headers: dict[str, list[str]]) -> datetime | None:
    """Newest Received line carries the receiving MTA's timestamp after the
    final ';'. Compare Date: against this rather than 'now' so audits of
    archived mail still report meaningfully."""
    received = headers.get("received", [])
    if not received:
        return None
    newest = received[0]
    if ";" not in newest:
        return None
    ts_str = newest.rsplit(";", 1)[1].strip()
    try:
        dt = parsedate_to_datetime(ts_str)
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


async def run(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    headers = email.headers

    # ─── required headers present ────────────────────────────────────
    missing = [h for h in _REQUIRED_HEADERS if not headers.get(h)]
    if missing:
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.required_headers",
                severity=Severity.HIGH,
                passed=False,
                message=(
                    f"Required RFC 5322 header(s) missing: {missing}. "
                    "Filters add ~1.5 spam-points per missing header."
                ),
                details={"missing": missing},
            )
        )
    else:
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.required_headers",
                severity=Severity.INFO,
                passed=True,
                message="All required RFC 5322 headers present.",
            )
        )

    # ─── no duplicates of single-instance headers ────────────────────
    duplicates = [h for h in _NO_DUPLICATE_HEADERS if len(headers.get(h, [])) > 1]
    if duplicates:
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.duplicate_headers",
                severity=Severity.HIGH,
                passed=False,
                message=(
                    f"Duplicate single-instance header(s): {duplicates}. "
                    "Many MTAs reject; filters score this as malformed."
                ),
                details={"duplicates": duplicates},
            )
        )
    else:
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.duplicate_headers",
                severity=Severity.INFO,
                passed=True,
                message="No duplicate single-instance headers.",
            )
        )

    # ─── Date sanity ─────────────────────────────────────────────────
    date_hdr = headers.get("date", [])
    if not date_hdr:
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.date_sanity",
                severity=Severity.LOW,
                passed=False,
                message="No Date header: covered by required_headers above.",
            )
        )
    else:
        try:
            sent_at = parsedate_to_datetime(date_hdr[0])
            if sent_at is None:
                raise ValueError("None")
            if sent_at.tzinfo is None:
                sent_at = sent_at.replace(tzinfo=UTC)
        except (TypeError, ValueError):
            findings.append(
                Finding(
                    check=f"{CHECK_PREFIX}.date_sanity",
                    severity=Severity.MEDIUM,
                    passed=False,
                    message=f"Date header unparseable: {date_hdr[0][:80]!r}.",
                    details={"raw": date_hdr[0][:200]},
                )
            )
        else:
            received_at = _parse_received_date(headers)
            anchor = received_at or datetime.now(UTC)
            drift = abs((sent_at - anchor).total_seconds())
            drift_days = drift / 86400.0
            if drift_days > _DATE_DRIFT_DAYS:
                direction = "future" if sent_at > anchor else "past"
                findings.append(
                    Finding(
                        check=f"{CHECK_PREFIX}.date_sanity",
                        severity=Severity.MEDIUM,
                        passed=False,
                        message=(
                            f"Date is {drift_days:.1f} days in the {direction} "
                            f"vs receive time. SpamAssassin DATE_IN_{direction.upper()} "
                            "fires above 6h drift; >7d is heavily weighted."
                        ),
                        details={
                            "drift_days": round(drift_days, 1),
                            "sent_at": sent_at.isoformat(),
                            "received_at": (received_at.isoformat() if received_at else "now"),
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        check=f"{CHECK_PREFIX}.date_sanity",
                        severity=Severity.INFO,
                        passed=True,
                        message=f"Date within {drift_days:.1f}d of receive time.",
                    )
                )

    # ─── Message-ID well-formed ──────────────────────────────────────
    mid = headers.get("message-id", [])
    if not mid:
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.message_id",
                severity=Severity.LOW,
                passed=False,
                message="No Message-ID: covered by required_headers above.",
            )
        )
    elif not _MSG_ID_RX.match(mid[0]):
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.message_id",
                severity=Severity.MEDIUM,
                passed=False,
                message=(
                    f"Message-ID malformed: {mid[0][:120]!r}. RFC 5322 requires "
                    "<localpart@domain> shape."
                ),
                details={"raw": mid[0][:200]},
            )
        )
    else:
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.message_id",
                severity=Severity.INFO,
                passed=True,
                message="Message-ID well-formed.",
            )
        )

    return findings
