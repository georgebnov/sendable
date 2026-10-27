"""Zero-width + bidirectional override codepoint scanner.

Bidi overrides (U+202D/U+202E) are CRITICAL — canonical pattern in the
Apple Intelligence prompt-injection disclosure. Zero-width (U+200B..F,
U+2060, U+FEFF, U+00AD, etc.) is HIGH — common in homograph / spoofing
attacks and has no legitimate use in email body text.

Each hit carries its source (subject vs body), offset, and a context
snippet so the report tells the user *where* in the email to look rather
than making them re-audit to find it.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup

from ... import esp
from ...parse import ParsedEmail
from ...report import Finding
from ...severity import Severity

_BIDI_OVERRIDE = re.compile(r"[‭‮]")
# U+00AD (soft hyphen) intentionally excluded — legitimate hyphenation hint.
# Zero-width and invisible characters, written as escapes so the source stays
# readable and no editor can silently normalise them away.
#
# U+200D ZERO WIDTH JOINER is deliberately excluded. It is the mandatory joiner
# inside family, profession, flag, and skin-tone emoji, so including it scored
# HIGH on any copy carrying one such emoji. HIGH is 15 points against a hygiene
# budget of 20, which is roughly a fifth of the composite and enough to flip a
# clean email from GO to REVIEW. U+200B, U+200C and U+FEFF still cover the
# evasion this looks for: breaking a filtered word while it reads normally.
_ZERO_WIDTH = re.compile(
    "["
    "\u200b"  # zero width space
    "\u200c"  # zero width non-joiner
    "\u200e\u200f"  # left-to-right and right-to-left marks
    "\u2028-\u202c"  # line/paragraph separators and embedding controls
    "\u205f\u2060\u2064"  # medium math space, word joiner, invisible plus
    "\u2066-\u206f"  # isolate and deprecated formatting controls
    "\ufeff"  # byte order mark
    "]"
)
_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?\b",
    re.IGNORECASE,
)


def _collect_visible_parts(email: ParsedEmail) -> list[tuple[str, str]]:
    """Return labeled visible-text parts: [(source, text), ...].

    Hidden-CSS elements are decomposed from the HTML before extraction —
    those belong to the hidden_css check, not this one.
    """
    parts: list[tuple[str, str]] = []
    if email.subject:
        parts.append(("subject", email.subject))
    if email.html:
        soup = BeautifulSoup(email.html, "lxml")
        for el in soup.find_all(style=_HIDDEN_STYLE):
            el.decompose()
        parts.append(("body (html)", soup.get_text(separator=" ")))
    if email.plain_text:
        parts.append(("body (text)", email.plain_text))
    return parts


def _snippet(text: str, pos: int, radius: int = 40) -> str:
    """Context window around `pos`, with the offending char marked «U+XXXX»."""
    start = max(0, pos - radius)
    end = min(len(text), pos + radius + 1)
    cp = f"{ord(text[pos]):04X}"
    lead = "…" if start > 0 else ""
    tail = "…" if end < len(text) else ""
    before = text[start:pos].replace("\n", "↵").replace("\r", "")
    after = text[pos + 1 : end].replace("\n", "↵").replace("\r", "")
    return f"{lead}{before}«U+{cp}»{after}{tail}"


async def run(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    bidi_hits: list[dict] = []
    zw_hits: list[dict] = []

    for source, text in _collect_visible_parts(email):
        for m in _BIDI_OVERRIDE.finditer(text):
            bidi_hits.append(
                {
                    "source": source,
                    "offset": m.start(),
                    "codepoint": hex(ord(m.group(0))),
                    "context": _snippet(text, m.start()),
                }
            )
        for m in _ZERO_WIDTH.finditer(text):
            zw_hits.append(
                {
                    "source": source,
                    "offset": m.start(),
                    "codepoint": hex(ord(m.group(0))),
                    "context": _snippet(text, m.start()),
                }
            )

    def _source_summary(hits: list[dict]) -> str:
        counts: dict[str, int] = {}
        for h in hits:
            counts[h["source"]] = counts.get(h["source"], 0) + 1
        return ", ".join(f"{s} ×{n}" for s, n in counts.items())

    if bidi_hits:
        findings.append(
            Finding(
                check="content.bidi_override",
                severity=Severity.CRITICAL,
                passed=False,
                message=(
                    f"The message holds {len(bidi_hits)} invisible character that "
                    f"reverses reading direction, in {_source_summary(bidi_hits)}. "
                    "These let text display in one order and read in another, which "
                    "is how a link is disguised. Paste your copy into a plain text "
                    "editor and retype it to clear them."
                ),
                details={
                    "count": len(bidi_hits),
                    "codepoints": sorted({h["codepoint"] for h in bidi_hits}),
                    "locations": [
                        f"{h['source']} @ char {h['offset']}: {h['context']}"
                        for h in bidi_hits[:10]
                    ],
                },
            )
        )
    else:
        findings.append(
            Finding(
                check="content.bidi_override",
                severity=Severity.INFO,
                passed=True,
                message="No bidirectional override characters.",
            )
        )

    if zw_hits:
        # Subject is user-controlled — any zero-widths there stay HIGH
        # regardless of ESP. Only body-only hits get demoted, since ESPs
        # commonly inject U+200B around footer / social / unsubscribe.
        subject_hits = any(h["source"] == "subject" for h in zw_hits)
        detected = None if subject_hits else esp.detect(email)
        # Narrowed profile rather than a bool, so chrome.name below type-checks.
        chrome = detected if (detected is not None and detected.is_high_confidence()) else None
        if chrome is not None:
            severity = Severity.INFO
            source = "esp_template"
            message = (
                f"Zero-width / invisible characters detected "
                f"({len(zw_hits)} in {_source_summary(zw_hits)}). "
                f"Located in body only: {chrome.name} injects these around "
                f"footer / social / unsubscribe blocks. Template chrome, not "
                f"user content."
            )
        else:
            severity = Severity.HIGH
            source = "user_content"
            message = (
                f"Zero-width / invisible characters detected "
                f"({len(zw_hits)} in {_source_summary(zw_hits)})."
            )
        findings.append(
            Finding(
                check="content.zero_width",
                severity=severity,
                passed=False,
                message=message,
                details={
                    "count": len(zw_hits),
                    "codepoints": sorted({h["codepoint"] for h in zw_hits}),
                    "locations": [
                        f"{h['source']} @ char {h['offset']}: {h['context']}" for h in zw_hits[:10]
                    ],
                    "esp": detected.name if detected else None,
                },
                source=source,
            )
        )
    else:
        findings.append(
            Finding(
                check="content.zero_width",
                severity=Severity.INFO,
                passed=True,
                message="No zero-width / invisible characters.",
            )
        )

    return findings
