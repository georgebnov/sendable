"""Template-quality checks: detect emails that look broken or are test
sends. These are signals that filters (Gmail/Yahoo/Outlook) treat as
phishing-shape or low-quality and route to spam.

Checks:
  - content.empty_href: anchor tags with empty/whitespace href.
  - content.merge_tag_unfilled: unrendered Mustache/Brevo/Jinja-style
    placeholders, empty greeting names ("Hi ,"), or empty inline
    formatting tags adjacent to a greeting.
  - content.body_visible_text_min: visible (post-strip) text below a
    minimum threshold while bulk-shaped, indicating mostly-empty
    template content the recipient cannot read.
  - headers.template_test_send: ESP test-send headers (e.g. Brevo
    `X-Mailin-Type: template-test`) — production sends never carry
    these.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup

from ...parse import ParsedEmail
from ...report import Finding
from ...severity import Severity

# Greeting words followed by an empty bound (comma/colon/punctuation) with
# nothing meaningful in between. Catches plain text "Hi ," "Hello ," and
# similar constructs after we strip empty inline tags from HTML.
# A greeting whose name is MISSING, which is what an unfilled merge field leaves
# behind: "Hi ," or "Hello  :" with a gap where the name should be.
#
# The whitespace was `*`, so this matched a greeting followed directly by
# punctuation, which is every ordinary "Hi," in every newsletter, plus "Hi, Sam"
# with the comma before the name, plus the word "hello" anywhere in prose. Each
# hit is HIGH against a hygiene budget of 20, which took that sub-score to 0 and
# moved an otherwise clean email down a verdict.
#
# It now needs at least one whitespace character between the greeting and the
# punctuation, which is the gap the missing name left, and it must sit at the
# start of a line or block rather than anywhere in the body.
_GREETING_EMPTY_RX = re.compile(
    r"(?:^|[\r\n>])\s*(hi|hello|hey|dear|greetings)\b[\s\u00a0]+[,:;.!]",
    re.IGNORECASE | re.MULTILINE,
)

# Unrendered placeholder syntaxes. We match conservatively: only flag when
# tokens look unmistakably like merge fields ESPs use, not arbitrary curly
# braces in code samples.
_PLACEHOLDER_RXS = (
    re.compile(r"\{\{\s*[A-Za-z_][\w\.\- ]*\s*\}\}"),  # {{ first_name }}
    re.compile(r"\{%\s*[A-Za-z_][\w\.\- ]*\s*%\}"),  # {% name %}
    re.compile(r"\{!\s*[A-Za-z_][\w\.\- ]*\s*!\}"),  # {! contact.FIRSTNAME !}
    re.compile(r"%%\s*[A-Za-z_][\w\.\- ]*\s*%%"),  # %%first_name%%
    re.compile(r"\*\|\s*[A-Za-z_][\w\.\- ]*\s*\|\*"),  # *|FNAME|* (Mailchimp)
    re.compile(r"\[\[\s*[A-Za-z_][\w\.\- ]*\s*\]\]"),  # [[ first_name ]]
)

# Inline tags whose emptiness inside a greeting context indicates an
# unfilled merge field (e.g. "Hi <strong></strong>,").
_EMPTY_INLINE_TAGS = ("strong", "b", "span", "em", "i")

# ESP test-send headers. Production campaigns never carry these.
_TEST_HEADER_VALUES = {
    "x-mailin-type": ("template-test", "test"),  # Brevo / Sendinblue
}
_TEST_HEADER_PRESENCE = ("x-test", "x-preview-send", "x-test-send")

# Visible-text minimum (chars). Below this, a bulk-shaped email is almost
# certainly a broken template — recipient sees an empty card with a CTA.
_VISIBLE_TEXT_MIN = 100

_BULK_SIGNAL_HEADERS = (
    "list-id",
    "feedback-id",
    "list-unsubscribe",
    "x-mailchimp-campaign-id",
    "x-campaign",
    "x-campaign-id",
)


def _is_bulk(email: ParsedEmail) -> bool:
    return any(email.headers.get(h) for h in _BULK_SIGNAL_HEADERS)


def _strip_empty_inline_tags(soup: BeautifulSoup) -> None:
    """Drop empty <strong>/<b>/<span> etc. so greeting regexes can match
    'Hi ,' that came from HTML 'Hi <strong></strong>,'."""
    for name in _EMPTY_INLINE_TAGS:
        for tag in soup.find_all(name):
            if not tag.get_text(strip=True) and not tag.find_all(True):
                tag.decompose()


def _check_empty_href(email: ParsedEmail) -> Finding:
    if not email.html:
        return Finding(
            check="content.empty_href",
            severity=Severity.INFO,
            passed=True,
            message="No HTML body to scan for empty hrefs.",
        )
    soup = BeautifulSoup(email.html, "lxml")
    offenders: list[dict] = []
    for a in soup.find_all("a"):
        href = a.get("href")
        text = a.get_text(separator=" ", strip=True)
        if href is None or not str(href).strip():
            offenders.append(
                {
                    "text": (text or "")[:60],
                    "href": "" if href is None else str(href)[:60],
                }
            )
    if offenders:
        return Finding(
            check="content.empty_href",
            severity=Severity.HIGH,
            passed=False,
            message=(
                f"{len(offenders)} anchor(s) have empty href. Recipients see a "
                f"clickable button that goes nowhere; filters score this as "
                f"phishing-shape."
            ),
            details={"offenders": offenders[:5], "count": len(offenders)},
        )
    return Finding(
        check="content.empty_href",
        severity=Severity.INFO,
        passed=True,
        message="All anchors have non-empty href.",
    )


def _check_merge_tag_unfilled(email: ParsedEmail) -> Finding:
    sources: list[tuple[str, str]] = []
    if email.html:
        soup = BeautifulSoup(email.html, "lxml")
        for tag in soup(["script", "style"]):
            tag.decompose()
        _strip_empty_inline_tags(soup)
        sources.append(("html", soup.get_text(separator=" ", strip=True)))
    if email.plain_text:
        sources.append(("plain", email.plain_text))
    if email.subject:
        sources.append(("subject", email.subject))

    hits: list[dict] = []
    for where, text in sources:
        for rx in _PLACEHOLDER_RXS:
            for m in rx.finditer(text):
                hits.append({"where": where, "kind": "placeholder", "match": m.group(0)})
        for m in _GREETING_EMPTY_RX.finditer(text):
            hits.append({"where": where, "kind": "empty_greeting", "match": m.group(0)})

    if hits:
        return Finding(
            check="content.merge_tag_unfilled",
            severity=Severity.HIGH,
            passed=False,
            message=(
                f"{len(hits)} unfilled merge field(s) detected. The recipient "
                f"sees a placeholder or empty name where personalization was "
                f"expected: filters treat this as broken/test mail."
            ),
            details={"hits": hits[:5], "count": len(hits)},
        )
    return Finding(
        check="content.merge_tag_unfilled",
        severity=Severity.INFO,
        passed=True,
        message="No unfilled merge tags or empty greetings detected.",
    )


def _check_body_visible_text_min(email: ParsedEmail) -> Finding:
    if not email.html:
        return Finding(
            check="content.body_visible_text_min",
            severity=Severity.INFO,
            passed=True,
            message="No HTML body to measure.",
        )
    soup = BeautifulSoup(email.html, "lxml")
    for tag in soup(["script", "style"]):
        tag.decompose()
    visible = soup.get_text(separator=" ", strip=True)
    visible_chars = len(visible)
    bulk = _is_bulk(email)

    if visible_chars < _VISIBLE_TEXT_MIN:
        sev = Severity.MEDIUM if bulk else Severity.LOW
        return Finding(
            check="content.body_visible_text_min",
            severity=sev,
            passed=False,
            message=(
                f"Visible body text is {visible_chars} chars (< {_VISIBLE_TEXT_MIN}). "
                f"Bulk-shaped emails this empty look like broken templates to filters."
            ),
            details={"visible_chars": visible_chars, "min": _VISIBLE_TEXT_MIN, "is_bulk": bulk},
        )
    return Finding(
        check="content.body_visible_text_min",
        severity=Severity.INFO,
        passed=True,
        message=f"Visible body text {visible_chars} chars (>= {_VISIBLE_TEXT_MIN}).",
        details={"visible_chars": visible_chars},
    )


def _check_template_test_send(email: ParsedEmail) -> Finding:
    matches: list[dict] = []
    for header, needles in _TEST_HEADER_VALUES.items():
        for raw in email.headers.get(header, []):
            low = raw.lower()
            if any(n in low for n in needles):
                matches.append({"header": header, "value": raw[:120]})
    for header in _TEST_HEADER_PRESENCE:
        for raw in email.headers.get(header, []):
            matches.append({"header": header, "value": raw[:120]})
    if matches:
        return Finding(
            check="headers.template_test_send",
            severity=Severity.HIGH,
            passed=False,
            message=(
                "ESP test-send header detected. Production campaigns should not "
                "carry test-send markers; recipients' filters down-rank these."
            ),
            details={"matches": matches},
        )
    return Finding(
        check="headers.template_test_send",
        severity=Severity.INFO,
        passed=True,
        message="No ESP test-send headers detected.",
    )


async def run(email: ParsedEmail) -> list[Finding]:
    return [
        _check_empty_href(email),
        _check_merge_tag_unfilled(email),
        _check_body_visible_text_min(email),
        _check_template_test_send(email),
    ]
