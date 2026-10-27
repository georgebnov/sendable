"""The advice an unaligned-SPF finding gives.

The finding told the sender to move the bounce domain onto a subdomain and
stopped there. Senders read that as "my SPF record is the problem" and add the
ESP's `include:` to their apex record, which changes nothing: SPF is evaluated
against the envelope sender, and on a shared ESP pool that is the ESP's own
domain. The message has to close that door, because it is the one the reader
walks through.
"""

from __future__ import annotations

import asyncio

from engine.domain.auth import alignment
from engine.parse import ParsedEmail, parse_eml
from engine.report import Finding


def _unaligned_spf() -> ParsedEmail:
    """A send through a shared ESP pool: SPF passes, for the ESP's own domain."""
    return parse_eml(
        b"Return-Path: <bounces-1=jane=example.com@pool.esp.example>\r\n"
        b"From: Jane <jane@example.com>\r\n"
        b"To: reader@gmail.com\r\n"
        b"Subject: Open house\r\n"
        b"Authentication-Results: mx.google.com; spf=pass; dkim=pass "
        b"header.i=@example.com; dmarc=pass (p=NONE)\r\n"
        b"Content-Type: text/plain\r\n\r\nHello.\r\n"
    )


def _finding(findings: list[Finding], check: str) -> Finding:
    return next(f for f in findings if f.check == check)


def test_unaligned_spf_says_not_to_change_the_apex_spf_record() -> None:
    findings = asyncio.run(alignment.run(_unaligned_spf()))
    spf = _finding(findings, "auth.dmarc_alignment_spf")

    assert spf.passed is False
    # The fix and the non-fix, in the same sentence. Naming only the fix is what
    # sent senders to their apex record in the first place.
    assert "apex SPF" in spf.message
    assert "envelope sender" in spf.message


def test_unaligned_spf_still_names_both_domains() -> None:
    findings = asyncio.run(alignment.run(_unaligned_spf()))
    spf = _finding(findings, "auth.dmarc_alignment_spf")

    assert "esp.example" in spf.message
    assert "example.com" in spf.message
    assert spf.details["from_org"] == "example.com"
    assert spf.details["return_path_org"] == "esp.example"
