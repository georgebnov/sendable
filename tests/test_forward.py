"""Forward detection, content extraction, and score muting.

A forwarded email must grade the original campaign (content extracted) with the
scrambled auth/transport/hidden-char checks muted, so a healthy send stops
reading as 9/100 just because it was forwarded.
"""

from __future__ import annotations

from email.message import EmailMessage

from engine.forward import (
    calibrate_for_forward,
    extract_original,
    is_forwarded,
)
from engine.parse import ParsedEmail
from engine.report import Finding
from engine.severity import Severity


def _email(*, subject=None, plain=None, html=None, ar=()):
    return ParsedEmail(
        raw=EmailMessage(),
        headers={},
        html=html,
        plain_text=plain,
        from_addr=None,
        to_addrs=[],
        subject=subject,
        authentication_results=list(ar),
        received_at=None,
    )


def test_a_subject_prefix_alone_is_not_a_forward():
    # This test previously asserted that a bare "Fwd:" or "FW:" subject made a
    # message a forward. Being read as a forward mutes the adversarial-content
    # Being read as a forward mutes the adversarial-content CRITICALs, so a
    # sender could disable them by typing "FW:" into their own subject line. The
    # prefix now counts only alongside the original's quoted header block.
    assert is_forwarded(_email(subject="Fwd: hello")) is False
    assert is_forwarded(_email(subject="FW: hello")) is False
    assert is_forwarded(_email(subject="a normal subject")) is False
    quoted = "From: a@b.com\nDate: Mon, 1 Sep 2026 10:00:00 +0000\nSubject: hello\nTo: c@d.com"
    assert is_forwarded(_email(subject="FW: hello", plain=quoted)) is True


def test_a_bare_body_marker_is_not_a_forward():
    # This test previously asserted the opposite. The marker line is typed by
    # whoever wrote the message, exactly like the "FW:" subject prefix closed
    # earlier, and it can sit inside a display:none div where no reader sees it.
    # On its own it cleared the DMARC alignment hard gate and muted the
    # authentication and transport findings, for precisely the senders that gate
    # exists to catch.
    e = _email(subject="x", plain="---------- Forwarded message ---------\nFrom: a")
    assert is_forwarded(e) is False


def test_a_body_marker_with_the_quoted_headers_is_a_forward():
    # A real inline forward carries the original's header block, which a sender
    # cannot produce without actually quoting a message.
    e = _email(
        subject="x",
        plain=(
            "---------- Forwarded message ---------\n"
            "From: a@b.com\nDate: Mon, 1 Sep 2026 10:00:00 +0000\n"
            "Subject: hello\nTo: c@d.com\n\nThe body."
        ),
    )
    assert is_forwarded(e) is True


def test_a_gappssmtp_signature_alone_is_not_a_forward():
    # This test previously asserted the opposite. A Google Workspace domain with
    # no custom DKIM signs EVERY direct send as d=<domain>.<date>.gappssmtp.com,
    # so reading that as a forward cleared the DMARC alignment hard gate for
    # exactly the senders it exists to catch, and told them about "the account
    # that forwarded this" for mail nobody forwarded.
    e = _email(subject="x", ar=["dkim=pass header.d=abc.gappssmtp.com"])
    assert is_forwarded(e) is False


def test_extract_strips_subject_and_forward_header():
    e = _email(
        subject="Fwd: Summer got away",
        plain=(
            "---------- Forwarded message ---------\n"
            "From: a@b.com\nDate: Mon\nSubject: Summer got away\nTo: c@d.com\n\n"
            "The real campaign body."
        ),
    )
    o = extract_original(e)
    assert o.subject == "Summer got away"
    assert o.plain_text == "The real campaign body."


def test_extract_strips_gmail_quote_html():
    html = (
        '<div dir="ltr">fyi</div>'
        '<div class="gmail_quote">'
        '<div class="gmail_attr">On Mon, someone wrote:</div>'
        "<p>Original campaign copy</p></div>"
    )
    o = extract_original(_email(subject="Fwd: x", html=html))
    assert "Original campaign copy" in o.html
    assert "gmail_attr" not in o.html
    assert "someone wrote" not in o.html


def test_calibrate_mutes_scrambled_checks_only():
    findings = [
        Finding(
            check="auth.tls_transport",
            severity=Severity.HIGH,
            passed=False,
            message="no tls",
            hard_gate=True,
        ),
        Finding(
            check="sending_ip.ptr_resolves", severity=Severity.HIGH, passed=False, message="no ptr"
        ),
        Finding(
            check="copywriting.reading_level",
            severity=Severity.MEDIUM,
            passed=False,
            message="grade 10",
        ),
    ]
    out = calibrate_for_forward(findings)

    tls = next(f for f in out if f.check == "auth.tls_transport")
    assert tls.severity is Severity.INFO  # muted → zero penalty
    assert tls.hard_gate is False  # gate cleared
    assert "Muted" in tls.message

    # A real content finding is untouched.
    cw = next(f for f in out if f.check == "copywriting.reading_level")
    assert cw.severity is Severity.MEDIUM

    # One advisory appended.
    assert any(f.check == "delivery.forwarded" for f in out)


def test_forward_dkim_alignment_reframed_as_forwarder_note():
    findings = [
        Finding(
            check="auth.dmarc_alignment_dkim",
            severity=Severity.HIGH,
            passed=False,
            message="DKIM not aligned: signed by gappssmtp.com...",
            hard_gate=True,
            details={"dkim_d": ["gappssmtp.com"], "from_org": "moralespropertygroup.com"},
        ),
    ]
    out = calibrate_for_forward(findings)
    f = next(x for x in out if x.check == "auth.dmarc_alignment_dkim")
    assert f.severity is Severity.INFO  # off the campaign score
    assert f.hard_gate is False
    assert "gappssmtp.com" in f.message  # the real signer surfaces
    assert "moralespropertygroup.com" in f.message  # their domain
    assert "Muted" not in f.message  # reframed, not buried as generic noise


def test_calibrate_noop_when_nothing_to_mute():
    findings = [
        Finding(
            check="copywriting.reading_level", severity=Severity.MEDIUM, passed=False, message="x"
        ),
    ]
    out = calibrate_for_forward(findings)
    assert len(out) == 1  # no advisory added when nothing was muted
