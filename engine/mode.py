"""Test vs production mode detection.

Default is TEST. We flip to PRODUCTION only when no test signals fire.
A test send that slips through as production would be scored at full
severity (missing unsub = HARD GATE etc) and produce a misleading
report. The opposite (production scored as test) just runs cleanup
that finds nothing to clean — a no-op.

Detection is heuristic. Each fired signal contributes one point.
Score >= 1 → TEST. We surface the fired signals in the result so the
report can show the user exactly why we picked the mode.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .parse import ParsedEmail

_TEST_SUBJECT_PREFIX_RX = re.compile(
    r"^\s*(test|preview|sandbox|dev|staging|draft|qa|uat)\s*[\-:_\]\)|]",
    re.IGNORECASE,
)

_TEST_PLUS_ADDR_RX = re.compile(r"\+(audit|test|preview|qa|staging|dev)@", re.IGNORECASE)

# Headers that ESPs add only on test/preview sends. Real campaigns never
# carry them. Same list cleanup.py uses to strip headers.
TEST_HEADER_NAMES = (
    "x-test",
    "x-test-send",
    "x-preview-send",
    "x-mailchimp-test",
    "x-mailgun-test",
    "x-klaviyo-test",
    "x-hubspot-test",
    "x-sendgrid-test",
    "x-ac-test",
    "x-brevo-test",
)
TEST_HEADER_VALUE_NEEDLES = {
    "x-mailin-type": ("template-test", "test"),
}

# Merge-tag syntaxes. Presence in body (raw, unrendered) implies the
# email never went through ESP variable substitution → test send.
_MERGE_TAG_RXS = (
    re.compile(r"\{\{\s*[A-Za-z_][\w\.\- ]*\s*(\|[^\}]+)?\s*\}\}"),
    re.compile(r"\{%\s*[A-Za-z_][\w\.\- ]*\s*%\}"),
    re.compile(r"\*\|\s*[A-Za-z_][\w\.\- ]*\s*\|\*"),
    # A merge tag, not percent-encoding. The interior must contain something
    # that is not a hex digit, because "%C3%" and "%E2%" are the lead bytes of
    # any UTF-8 character in a tracking link, which encoders emit in uppercase
    # hex. Without this, ordinary campaign HTML was labelled a test send and
    # cleanup rewrote its links before the link checks read them.
    re.compile(r"%(?=[A-Z0-9_]*[G-Z_])[A-Z][A-Z0-9_]+%"),
    re.compile(r"%%\s*[A-Za-z_][\w\.\- ]*\s*%%"),
    re.compile(r"\[\[\s*[A-Za-z_][\w\.\- ]*\s*\]\]"),
)

# Keyword-gated single-bracket detector. Mirror of the cleanup-side rule:
# any `[…]` whose interior carries a personalization keyword AND is not an
# MSO Outlook conditional comment counts as an unfilled merge tag.
_BRACKET_PLACEHOLDER_RX = re.compile(r"\[([^\[\]\n]{1,80})\]")
_BRACKET_PLACEHOLDER_KEYWORDS = (
    "name",
    "first",
    "last",
    "full",
    "email",
    "company",
    "city",
    "country",
    "phone",
    "url",
    "link",
    "unsub",
    "merge",
    "tag",
    "field",
    "goes here",
    "fallback",
    "recipient",
    "subscriber",
)
_BRACKET_PLACEHOLDER_SKIP = ("if mso", "endif", "mso ", "outlook", "endif]")


def _body_has_bracket_placeholder(body_text: str) -> bool:
    for m in _BRACKET_PLACEHOLDER_RX.finditer(body_text):
        interior = m.group(1).strip().lower()
        if not interior or any(s in interior for s in _BRACKET_PLACEHOLDER_SKIP):
            continue
        if any(k in interior for k in _BRACKET_PLACEHOLDER_KEYWORDS):
            return True
    return False


@dataclass
class ModeResult:
    is_test: bool
    confidence: int
    signals: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return "TEST" if self.is_test else "PRODUCTION"


def detect(email: ParsedEmail, *, force: str | None = None) -> ModeResult:
    """Return ModeResult. `force` of 'test' or 'production' overrides
    heuristics for callers that want explicit control (CLI flag).
    """
    if force == "production":
        return ModeResult(is_test=False, confidence=0, signals=["forced=production"])
    if force == "test":
        return ModeResult(is_test=True, confidence=99, signals=["forced=test"])

    signals: list[str] = []

    for name in TEST_HEADER_NAMES:
        if email.headers.get(name):
            signals.append(f"header:{name}")
            break
    for name, needles in TEST_HEADER_VALUE_NEEDLES.items():
        values = email.headers.get(name, [])
        if any(any(n in v.lower() for n in needles) for v in values):
            signals.append(f"header:{name}")
            break

    if email.subject and _TEST_SUBJECT_PREFIX_RX.match(email.subject):
        signals.append("subject:test_prefix")

    for to in email.to_addrs or []:
        if _TEST_PLUS_ADDR_RX.search(to):
            signals.append("recipient:plus_address")
            break

    # Scan all composer-controlled surfaces: body, subject, From display
    # name. Any unfilled merge tag implies the send never went through
    # ESP variable substitution → test send.
    scan_corpus = "\n".join(
        s
        for s in (
            email.html,
            email.plain_text,
            email.subject,
            email.from_addr,
            *(email.headers.get("reply-to") or []),
        )
        if s
    )
    if scan_corpus.strip():
        matched = any(rx.search(scan_corpus) for rx in _MERGE_TAG_RXS)
        if not matched:
            matched = _body_has_bracket_placeholder(scan_corpus)
        if matched:
            signals.append("body:merge_tags")

    return ModeResult(
        is_test=bool(signals),
        confidence=len(signals),
        signals=signals,
    )
