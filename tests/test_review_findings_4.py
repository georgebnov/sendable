"""Regressions for the fourth review round.

Three of these are a defect class an earlier round already fixed somewhere else,
and one is a bug I half-fixed: round 3 stopped a typed body marker muting the
hidden-content checks and left it clearing the DMARC alignment gate.
"""

from __future__ import annotations

import asyncio

import pytest

from engine import esp as esp_detect
from engine.dmarc.policy_engine import (
    DmarcRecord as PolicyRecord,
)
from engine.dmarc.policy_engine import (
    Sender,
    Window,
    _build_record,
    dmarc_decision,
)
from engine.domain.integrity import invisible_chars
from engine.mode import detect
from engine.parse import ParsedEmail, parse_eml
from engine.runner import audit


def _email(body: bytes, *, headers: bytes = b"", subject: bytes = b"Open house") -> ParsedEmail:
    return parse_eml(
        b"From: Jane <jane@example.com>\r\nTo: r@gmail.com\r\nSubject: "
        + subject
        + b"\r\n"
        + headers
        + b"Content-Type: text/html; charset=utf-8\r\n\r\n<html><body>"
        + body
        + b"</body></html>"
    )


# ── the record the tool tells you to paste ─────────────────────────────────


def test_the_suggested_record_keeps_the_tags_it_is_not_changing() -> None:
    """This is the single most consequential string the tool emits.

    SKILL.md tells the agent to have the user publish `next_step.new_record`. A
    user at `p=none; sp=reject; adkim=s; aspf=s` who followed ADVANCE pasted
    `p=quarantine; rua=...; pct=25` and silently lost subdomain enforcement and
    strict alignment, because the builder emitted only the tags it set.
    """
    current = PolicyRecord(exists=True, p="none", sp="reject", adkim="s", aspf="s")
    record = _build_record("quarantine", 25, "dmarc@example.com", current=current)
    assert "p=quarantine" in record
    assert "sp=reject" in record, f"subdomain policy was dropped: {record}"
    assert "adkim=s" in record, f"strict DKIM alignment was dropped: {record}"
    assert "aspf=s" in record, f"strict SPF alignment was dropped: {record}"


def test_a_record_with_no_extra_tags_stays_minimal() -> None:
    current = PolicyRecord(exists=True, p="none")
    record = _build_record("quarantine", 100, "dmarc@example.com", current=current)
    assert "sp=" not in record
    assert "adkim=" not in record
    assert "aspf=" not in record


def test_the_builder_still_works_with_no_current_record() -> None:
    # PUBLISH_INITIAL has nothing to carry forward.
    record = _build_record("none", 100, "dmarc@example.com")
    assert record.startswith("v=DMARC1; p=none;")


# ── a typed marker must not clear the alignment gate ───────────────────────


def test_a_body_marker_does_not_clear_the_alignment_hard_gate() -> None:
    # Round 3 stopped this muting content.hidden_css_salting and left the DMARC
    # alignment gate, which is the gate the forward path exists to reason about.
    # The marker is typed by whoever wrote the message.
    marker = b"<p>---------- Forwarded message ---------</p>"
    report = asyncio.run(audit(_email(marker + b"<p>Hello.</p>"), domain_health=False))
    alignment = next(
        (f for f in report.findings if f.check == "auth.dmarc_alignment_overall"), None
    )
    assert alignment is not None
    assert alignment.severity == "CRITICAL", "a typed marker cleared the alignment gate"
    assert "auth.dmarc_alignment_overall" in report.hard_gates_failed


def test_a_genuine_forward_still_reframes_the_alignment_finding() -> None:
    # A real forward carries the original's quoted headers. There the note about
    # the forwarding account is correct and useful.
    raw = (
        b"From: Sam <sam@example.net>\r\nTo: r@gmail.com\r\nSubject: Fwd: Open house\r\n\r\n"
        b"Have a look.\r\n\r\n---------- Forwarded message ---------\r\n"
        b"From: Jane <jane@example.com>\r\nDate: Mon, 1 Sep 2026 10:00:00 +0000\r\n"
        b"Subject: Open house\r\nTo: sam@example.net\r\n\r\nThe open house runs from noon.\r\n"
    )
    report = asyncio.run(audit(parse_eml(raw), domain_health=False))
    assert "auth.dmarc_alignment_overall" not in report.hard_gates_failed


# ── ESP detection must not trust a forgeable header ────────────────────────


def test_an_unverified_dkim_signature_does_not_identify_the_provider() -> None:
    # Any sender can write DKIM-Signature: d=kit.com. A high-confidence profile
    # makes run_domain_health skip the ENTIRE IP blocklist scan, so a listed
    # spammer could disable it with one header.
    email = parse_eml(
        b"From: Spammer <s@shady.test>\r\nTo: r@gmail.com\r\nSubject: hi\r\n"
        b"DKIM-Signature: v=1; a=rsa-sha256; d=kit.com; s=x; h=from; bh=a; b=b\r\n\r\nbody"
    )
    profile = esp_detect.detect(email)
    assert profile is None or not profile.is_high_confidence(), (
        "an unverified d= tag reached high confidence and would skip the blocklist scan"
    )


def test_a_verified_dkim_signature_still_identifies_the_provider() -> None:
    email = parse_eml(
        b"From: Jane <jane@example.com>\r\nTo: r@gmail.com\r\nSubject: hi\r\n"
        b"DKIM-Signature: v=1; a=rsa-sha256; d=kit.com; s=x; h=from; bh=a; b=b\r\n"
        b"Authentication-Results: mx.google.com; dkim=pass header.d=kit.com\r\n\r\nbody"
    )
    profile = esp_detect.detect(email)
    assert profile is not None
    assert profile.name.startswith("Kit")


def test_a_lookalike_unsubscribe_host_is_not_matched() -> None:
    # Same lookalike class as the PTR match, the fourth place it appeared.
    email = parse_eml(
        b"From: Spammer <s@shady.test>\r\nTo: r@gmail.com\r\nSubject: hi\r\n"
        b"List-Unsubscribe: <https://u.toolkit.com/unsub?x=1>\r\n\r\nbody"
    )
    profile = esp_detect.detect(email)
    assert profile is None or "Kit" not in profile.name, "u.toolkit.com matched kit.com"


def test_a_real_unsubscribe_host_is_still_matched() -> None:
    email = parse_eml(
        b"From: Jane <jane@example.com>\r\nTo: r@gmail.com\r\nSubject: hi\r\n"
        b"List-Unsubscribe: <https://unsubscribe.kit.com/u?x=1>\r\n\r\nbody"
    )
    profile = esp_detect.detect(email)
    assert profile is not None
    assert profile.name.startswith("Kit")


# ── a hop nobody controls must not trigger a policy rollback ───────────────


def test_an_uncontrollable_gateway_never_triggers_a_rollback() -> None:
    # _UNCONTROLLABLE_TAGS says these must "never" produce a policy rollback. Once
    # the relay carried 20% of volume the share test fired anyway, and the tool
    # handed over a record weakening anti-spoofing to fix a hop nobody can fix.
    relay = Sender(
        name="Mimecast relay",
        volume=30,
        dkim_aligned=False,
        spf_aligned=False,
        spf_authpassed=False,
        has_dkim_signature=False,
        legitimacy="legit",
        disposition="reject",
        classification="gateway_relay",
    )
    aligned = Sender(
        name="Microsoft 365",
        volume=70,
        dkim_aligned=True,
        spf_aligned=True,
        spf_authpassed=True,
        has_dkim_signature=True,
        legitimacy="legit",
        disposition="none",
        classification="clean",
    )
    window = Window(
        senders=[aligned, relay], clean_streak_days=0, days_with_data=10, total_volume=100
    )
    decision = dmarc_decision(PolicyRecord(exists=True, p="reject"), window, "dmarc@example.com")
    assert decision.code != "ROLLBACK", f"a gateway produced {decision.code}"
    assert decision.new_record is None, "no record weakening for an unfixable hop"


def test_a_controllable_sender_bleeding_still_can_roll_back() -> None:
    # The rollback exists for a real reason: the user's own mail being rejected.
    esp = Sender(
        name="SendGrid",
        volume=30,
        dkim_aligned=False,
        spf_aligned=False,
        spf_authpassed=True,
        has_dkim_signature=True,
        legitimacy="legit",
        disposition="reject",
        classification="clean",
    )
    other = Sender(
        name="Mailchimp",
        volume=30,
        dkim_aligned=False,
        spf_aligned=False,
        spf_authpassed=True,
        has_dkim_signature=True,
        legitimacy="legit",
        disposition="reject",
        classification="clean",
    )
    window = Window(senders=[esp, other], clean_streak_days=0, days_with_data=10, total_volume=100)
    decision = dmarc_decision(PolicyRecord(exists=True, p="reject"), window, "dmarc@example.com")
    assert decision.code == "ROLLBACK"


# ── a joiner emoji is not an evasion ───────────────────────────────────────


def test_a_zero_width_joiner_emoji_is_not_reported() -> None:
    """A single emoji cost roughly a fifth of the composite score.

    U+200D ZERO WIDTH JOINER is the mandatory joiner inside family, profession,
    and flag emoji. It sits inside the U+200B..U+200F range the check scans, so
    ordinary copy with one such emoji scored HIGH against a hygiene budget of 20.

    A test of mine claimed to cover this and asserted only the bidi finding, so
    the zero-width finding fired unchecked. This asserts the right one.
    """
    email = _email("<p>Our team \U0001f469‍\U0001f4bb is here to help.</p>".encode())
    findings = asyncio.run(invisible_chars.run(email))
    zero_width = next((f for f in findings if f.check == "content.zero_width"), None)
    assert zero_width is not None
    assert zero_width.passed is True, "a joiner emoji was reported as hidden-character evasion"


@pytest.mark.parametrize(
    ("label", "text"),
    [
        ("zero-width space", "Free\u200bmoney today"),
        ("zero-width non-joiner", "Free‌money today"),
        ("byte order mark", "Free﻿money today"),
    ],
)
def test_a_real_hidden_character_is_still_reported(label: str, text: str) -> None:
    # A joiner between two emoji is structural. A zero-width space inside a word
    # is there to break a filter, and must still be caught.
    email = _email(f"<p>{text}</p>".encode())
    findings = asyncio.run(invisible_chars.run(email))
    zero_width = next((f for f in findings if f.check == "content.zero_width"), None)
    assert zero_width is not None
    assert zero_width.passed is False, f"{label} was not reported"


# ── a percent-encoded URL is not a merge tag ───────────────────────────────


@pytest.mark.parametrize(
    "href",
    [
        "https://example.com/t?u=caf%C3%A9",
        "https://example.com/t?q=it%E2%80%99s",
        "https://example.com/t?x=%D0%B0%D0%B1",
        "https://example.com/click?utm_term=%28brand%29",
    ],
)
def test_a_percent_encoded_url_does_not_flip_the_mode_to_test(href: str) -> None:
    # The merge-tag pattern %[A-Z][A-Z0-9_]+% matches %C3%, %E2%, and every other
    # UTF-8 lead byte, which encoders emit in uppercase hex. Tracking links make
    # this the common case for real campaign HTML, so production mail was labelled
    # a test send and cleanup rewrote its links before the link checks read them.
    email = _email(f'<a href="{href}">Read</a>'.encode())
    mode = detect(email)
    assert mode.is_test is False, f"{href} was read as a merge tag: {mode.signals}"


@pytest.mark.parametrize("tag", ["%FIRST_NAME%", "%RECIPIENT_CITY%", "%MERGE_FIELD%"])
def test_a_real_percent_merge_tag_is_still_detected(tag: str) -> None:
    email = _email(f"<p>Hi {tag},</p>".encode())
    assert detect(email).is_test is True, f"{tag} was not detected"
