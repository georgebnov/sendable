"""Bracket-placeholder cleanup tests.

ESP composers leave unsubstituted bracket tokens in test sends. The
cleanup pass must replace them with fake values so audit checks don't
flag them as ALL CAPS / weird capitalisation / spam triggers. The same
pass must NOT eat MSO Outlook conditional comments, which look bracketed
but are real layout directives.
"""

from __future__ import annotations

import sys
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.cleanup import cleanup  # noqa: E402
from audit.mode import detect  # noqa: E402
from audit.parse import ParsedEmail  # noqa: E402


def _email(*, subject: str = "Hello", html: str | None = None, plain: str | None = None) -> ParsedEmail:
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["Subject"] = subject
    if html:
        msg.set_content(plain or "", subtype="plain")
        msg.add_alternative(html, subtype="html")
    elif plain:
        msg.set_content(plain, subtype="plain")
    headers: dict[str, list[str]] = {}
    for k, v in msg.items():
        headers.setdefault(k.lower(), []).append(str(v))
    return ParsedEmail(
        raw=msg,
        headers=headers,
        html=html,
        plain_text=plain,
        from_addr="sender@example.com",
        to_addrs=[],
        subject=subject,
        authentication_results=[],
    )


def test_kit_first_name_goes_here_substituted():
    e = _email(html="<p>Hi [FIRST NAME GOES HERE], welcome.</p>")
    cleaned, report = cleanup(e)
    assert "[FIRST NAME GOES HERE]" not in cleaned.html
    assert any(p["field"] == "FIRST NAME GOES HERE" for p in report.placeholders_substituted)


def test_campaign_monitor_fallback_syntax_substituted():
    e = _email(html="<p>Hi [firstname,fallback=friend], welcome.</p>")
    cleaned, report = cleanup(e)
    assert "firstname,fallback=friend" not in cleaned.html
    assert report.placeholders_substituted


def test_constant_contact_recipient_firstname_substituted():
    e = _email(html="<p>Hi [Recipient FirstName].</p>")
    cleaned, report = cleanup(e)
    assert "[Recipient FirstName]" not in cleaned.html
    assert report.placeholders_substituted


def test_mso_conditional_comments_preserved():
    html = "<!--[if mso]><table><![endif]--><p>body</p><!--[if mso]><![endif]-->"
    e = _email(html=html)
    cleaned, _ = cleanup(e)
    assert "[if mso]" in cleaned.html
    assert "[endif]" in cleaned.html


def test_non_placeholder_bracket_passes_through():
    """Brackets carrying no placeholder keyword must not be substituted —
    e.g. tone tags, sectioning syntax, anchor labels."""
    e = _email(html="<p>Section [important] note here.</p>")
    cleaned, report = cleanup(e)
    assert "[important]" in cleaned.html
    assert not report.placeholders_substituted


def test_mode_detects_bracket_placeholder_as_test():
    """Test-vs-production detection must fire on Kit's unfilled bracket
    placeholders even when no other test signal is present."""
    e = _email(html="<p>Hi [FIRST NAME GOES HERE].</p>")
    result = detect(e)
    assert result.is_test
    assert "body:merge_tags" in result.signals


def test_subject_placeholder_substituted():
    e = _email(subject="Hi [FIRST NAME GOES HERE], welcome!", plain="body")
    cleaned, report = cleanup(e)
    assert "[FIRST NAME GOES HERE]" not in cleaned.subject
    assert any(p["field"] == "FIRST NAME GOES HERE" for p in report.placeholders_substituted)


def test_subject_jinja_merge_tag_substituted():
    e = _email(subject="Hi {{ first_name }}, news inside", plain="body")
    cleaned, report = cleanup(e)
    assert "{{" not in cleaned.subject
    assert report.placeholders_substituted


def test_from_display_name_placeholder_substituted_address_preserved():
    """Composer-set From display name can carry merge tags. Substitute
    the display half, leave the `<addr@dom>` exactly so SPF/DKIM/DMARC
    alignment checks still see the real domain."""
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["From"] = '"Hi {{first_name}}" <newsletter@example.com>'
    msg["Subject"] = "Hello"
    msg.set_content("body", subtype="plain")
    headers: dict[str, list[str]] = {}
    for k, v in msg.items():
        headers.setdefault(k.lower(), []).append(str(v))
    e = ParsedEmail(
        raw=msg,
        headers=headers,
        html=None,
        plain_text="body",
        from_addr=msg["From"],
        to_addrs=[],
        subject="Hello",
        authentication_results=[],
    )
    cleaned, report = cleanup(e)
    assert "{{" not in (cleaned.from_addr or "")
    assert "<newsletter@example.com>" in (cleaned.from_addr or "")
    assert report.placeholders_substituted


def test_mode_detects_subject_placeholder_as_test():
    e = _email(subject="Hi [FIRST NAME GOES HERE]", plain="body")
    assert detect(e).is_test


def test_mode_detects_from_display_placeholder_as_test():
    e = _email(plain="body")
    e.from_addr = '"Hi {{first_name}}" <a@b.com>'
    e.headers["from"] = [e.from_addr]
    assert detect(e).is_test
