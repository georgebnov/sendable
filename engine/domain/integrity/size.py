"""HTML body byte size. Gmail clips above ~102KB; target below 90KB."""

from __future__ import annotations

from ...parse import ParsedEmail
from ...report import Finding
from ...severity import Severity

TARGET_BYTES = 90_000
GMAIL_CLIP_BYTES = 102_000


async def run(email: ParsedEmail) -> list[Finding]:
    if email.html is None:
        return [
            Finding(
                check="size.html_present",
                severity=Severity.MEDIUM,
                passed=False,
                message="No text/html body found.",
            )
        ]
    byte_len = len(email.html.encode("utf-8"))
    if byte_len > GMAIL_CLIP_BYTES:
        return [
            Finding(
                check="size.html_bytes",
                severity=Severity.CRITICAL,
                passed=False,
                message=(
                    f"HTML is {byte_len:,} bytes, exceeds Gmail clip limit ({GMAIL_CLIP_BYTES:,})."
                ),
                details={"bytes": byte_len, "limit": GMAIL_CLIP_BYTES},
            )
        ]
    if byte_len > TARGET_BYTES:
        return [
            Finding(
                check="size.html_bytes",
                severity=Severity.HIGH,
                passed=False,
                message=f"HTML is {byte_len:,} bytes, above target {TARGET_BYTES:,}.",
                details={"bytes": byte_len, "limit": TARGET_BYTES},
            )
        ]
    return [
        Finding(
            check="size.html_bytes",
            severity=Severity.INFO,
            passed=True,
            message=f"HTML is {byte_len:,} bytes.",
            details={"bytes": byte_len},
        )
    ]
