"""Structured email extraction: raw `ParsedEmail` → `StructuredEmail`.

Single source of truth for "what are the writing-craft blocks in this
message." Downstream consumers (copywriting heuristics, storytelling
analysis, future LLM critic, memory store) read from `StructuredEmail`
instead of re-deriving body / preview / signature / P.S. each time.

Layered approach — each layer best-effort, falls back gracefully:

  1. `preview_text` — hidden-style HTML element near top of body (the
     industry preheader convention). Falls back to None.
  2. `greeting` — opening line matching greeting patterns ("Hi X,",
     "Hello,", "Hey there —"). One line, stripped from body_blocks.
  3. `footer` — last block matching legal/address/unsubscribe patterns.
     Stripped from body_blocks.
  4. `signature` — block between body and footer matching sign-off +
     name shape. Stripped from body_blocks.
  5. `ps` — paragraph starting with "P.S." (any spacing/punctuation
     variant). Stripped from body_blocks.
  6. `cta_blocks` — anchor elements with button-shaped styling or text
     matching CTA action verbs.
  7. `body_blocks` — what remains, in document order. The narrative.

All section extractors are heuristic. False positives biased toward
"keep in body_blocks" rather than "split out wrongly" — the storytelling
checks would rather analyze too much than too little.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup
from pydantic import BaseModel, Field

from ..parse import ParsedEmail

# ─── Patterns ──────────────────────────────────────────────────────────

# Hidden-style CSS used by ESPs to ship preheader text invisibly. Mirrors
# the patterns in `audit/domain/integrity/hidden_css.py` and the legacy
# copy in `memory/store.py` (which now delegates to this module).
_HIDDEN_STYLE_RX = re.compile(
    r"display\s*:\s*none"
    r"|visibility\s*:\s*hidden"
    r"|opacity\s*:\s*0(?:\.0+)?\b"
    r"|font-size\s*:\s*0(?:px|pt|em|rem)?\b"
    r"|mso-hide\s*:\s*all"
    r"|text-indent\s*:\s*-\d{3,}px"
    r"|left\s*:\s*-\d{3,}px"
    r"|top\s*:\s*-\d{3,}px",
    re.IGNORECASE,
)

# P.S. line variants: "P.S.", "PS:", "P. S.", "P.S.—", etc.
_PS_RX = re.compile(
    r"^\s*p\.?\s*s\.?(?:\s*[:.\-—–])?\s+",
    re.IGNORECASE,
)

# Greeting line: "Hi Name,", "Hello,", "Hey there —", "Dear Bob,".
# Case-insensitive, allows trailing punctuation. Capped at ~80 chars so
# we don't swallow a long opening sentence by accident.
_GREETING_RX = re.compile(
    r"^\s*(hi|hello|hey|dear|greetings|good\s+(?:morning|afternoon|evening))\b"
    r"[^.!?\n]{0,80}[,:—–-]?\s*$",
    re.IGNORECASE,
)

# CTA verbs in anchor text. Order matters — longer phrases first so they
# match before single-word fallbacks.
_CTA_VERB_RX = re.compile(
    r"^\s*(?:"
    r"book\s+(?:a|your)\s+\w+|"
    r"schedule\s+(?:a|your)\s+\w+|"
    r"reserve\s+(?:your|my)\s+\w+|"
    r"claim\s+(?:your|my)\s+\w+|"
    r"view\s+(?:the|all|details|listings?)|"
    r"see\s+(?:the|all|more|details|listings?)|"
    r"get\s+(?:started|access|the|your)|"
    r"download\s+\w+|"
    r"learn\s+more|"
    r"read\s+more|"
    r"shop\s+(?:now|the)|"
    r"join\s+(?:us|now|the)|"
    r"register|sign\s+up|book|schedule|reserve|"
    r"start\s+(?:now|here|today)"
    r")\b",
    re.IGNORECASE,
)

# Footer markers — physical address (street suffixes), "unsubscribe", or
# the canonical CAN-SPAM "you received this because" phrasing.
_FOOTER_HINT_RX = re.compile(
    r"unsubscribe"
    r"|you\s+(?:are\s+)?receiv(?:ing|ed)\s+this"
    r"|copyright\s*[©(c)]"
    r"|\b\d{1,5}\s+\w+\s+(?:st|street|ave|avenue|rd|road|blvd|boulevard|dr|drive|way|lane|ln|ct|court|pl|place|sq|square|suite|ste)\b"
    r"|all\s+rights\s+reserved",
    re.IGNORECASE,
)

# ASCII-art section header: line wrapped in `*`/`-`/`=` runs (≥6 chars on
# each side typical for Kit / Mailchimp templates) with title text in the
# middle. Examples:
#   "************ NAB 2026 Recap ************"
#   "---------- Product Update: Q3 Release ----------"
_SECTION_HEADER_RX = re.compile(
    r"^[\s]*([*\-=_~]{4,})\s+(.+?)\s+\1[\s]*$",
)


# Signature shape: sign-off line ("Thanks,", "Best,", "Cheers,",
# "— Name") followed by 1-4 name/title/contact lines.
_SIGNOFF_RX = re.compile(
    r"^\s*(thanks|thank\s+you|cheers|best|regards|sincerely|warmly|"
    r"talk\s+soon|talk\s+later|talk\s+next\s+time|"
    r"till\s+next\s+time|until\s+next\s+time|until\s+next\s+week|"
    r"yours|yours\s+truly|all\s+the\s+best|warm\s+regards|kind\s+regards|"
    r"with\s+\w+|stay\s+(?:tuned|well|safe)|catch\s+you\s+\w+|"
    r"more\s+soon|more\s+next\s+\w+|"
    r"cheers\s+(?:for\s+now|all)"
    r")[\s,.\-—–!]*$",
    re.IGNORECASE,
)


# ─── Data model ────────────────────────────────────────────────────────


class CTABlock(BaseModel):
    """A button-shaped or action-verb anchor in the body."""

    text: str
    href: str
    has_button_styling: bool = False  # inline style background/padding hints


class StructuredEmail(BaseModel):
    """All writing-craft blocks isolated from a parsed email.

    Conventions:
      - Strings are stripped of leading/trailing whitespace.
      - None means "not detected" — distinct from empty string.
      - `body_blocks` are paragraphs in document order, AFTER stripping
        out greeting / signature / footer / ps / preview blocks AND any
        ASCII-art section headers (those land in `section_headers`).
      - `section_headers` is the list of section title strings (with
        wrapping punctuation runs stripped) in document order. Useful
        for storytelling-arc analysis of multi-section newsletters.
      - The full preserved body lives in `raw_plain` / `raw_html` for any
        consumer that needs to re-derive its own thing.
    """

    subject: str | None = None
    preview_text: str | None = None
    greeting: str | None = None
    body_blocks: list[str] = Field(default_factory=list)
    section_headers: list[str] = Field(default_factory=list)
    cta_blocks: list[CTABlock] = Field(default_factory=list)
    ps: str | None = None
    signature: str | None = None
    footer: str | None = None
    word_count: int = 0
    raw_html: str | None = None
    raw_plain: str | None = None


# ─── Helpers ───────────────────────────────────────────────────────────


_BLOCK_TAGS = {
    "p",
    "div",
    "li",
    "tr",
    "td",
    "th",
    "br",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "blockquote",
    "section",
    "article",
    "header",
    "footer",
    "pre",
    "hr",
}


def _strip_to_text(html: str) -> str:
    """HTML → plain text with paragraph boundaries preserved.

    `BeautifulSoup.get_text(separator='\\n')` collapses adjacent block
    elements into a single newline, which breaks paragraph detection
    downstream. We insert a blank-line marker after every block element
    and after `<br>` so `_split_paragraphs` can see boundaries."""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style"]):
        tag.decompose()
    # Append a paragraph break sentinel after every block element. Use a
    # sentinel that survives get_text() and won't collide with content.
    SENTINEL = "␞"  # RECORD SEPARATOR display char, very rare
    for el in soup.find_all(_BLOCK_TAGS):
        el.append(SENTINEL)
    text = soup.get_text(separator=" ", strip=False)
    # Each sentinel → blank line. Collapse runs of sentinels.
    text = re.sub(f"{SENTINEL}+", "\n\n", text)
    # Collapse internal whitespace within each line.
    lines = [re.sub(r"\s+", " ", line).strip() for line in text.splitlines()]
    return "\n".join(lines)


def _split_paragraphs(text: str) -> list[str]:
    """Group consecutive non-empty lines as a paragraph. Blank lines
    delimit. Each paragraph is space-collapsed."""
    paragraphs: list[str] = []
    buf: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            if buf:
                paragraphs.append(" ".join(buf))
                buf = []
            continue
        buf.append(stripped)
    if buf:
        paragraphs.append(" ".join(buf))
    return paragraphs


def _extract_preview_text(html: str | None) -> str | None:
    """Preheader: first hidden-styled element with visible text. Mirrors
    the original logic from `memory/store.py:_extract_preheader`."""
    if not html:
        return None
    soup = BeautifulSoup(html, "html.parser")
    for el in soup.find_all(style=True):
        style = el.get("style", "") or ""
        if not _HIDDEN_STYLE_RX.search(style):
            continue
        text = el.get_text(separator=" ", strip=True)
        if text:
            return text
    return None


def _extract_cta_blocks(html: str | None) -> list[CTABlock]:
    """Anchor elements whose visible text matches a CTA action verb OR
    whose inline style has button-shaped properties (background-color +
    padding). De-duplicates on (text.lower(), href)."""
    if not html:
        return []
    soup = BeautifulSoup(html, "html.parser")
    seen: set[tuple[str, str]] = set()
    out: list[CTABlock] = []
    for a in soup.find_all("a"):
        href = (a.get("href") or "").strip()
        if not href:
            continue
        text = a.get_text(separator=" ", strip=True)
        if not text:
            continue
        style = (a.get("style") or "").lower()
        # Button styling: inline style declares a non-default background
        # plus padding. Crude but works on most ESP-built CTA buttons.
        has_button_styling = "background" in style and (
            "padding" in style or "border-radius" in style
        )
        is_cta = bool(_CTA_VERB_RX.match(text)) or has_button_styling
        if not is_cta:
            continue
        key = (text.lower(), href)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            CTABlock(
                text=text,
                href=href,
                has_button_styling=has_button_styling,
            )
        )
    return out


def _peel_greeting(paragraphs: list[str]) -> tuple[str | None, list[str]]:
    """Greeting can appear inside the first ~3 paragraphs — many ESP
    templates ship an ASCII-art header / section title before the
    greeting. Scan the head, return (greeting, paragraphs_with_it_removed)."""
    for i in range(min(3, len(paragraphs))):
        if _GREETING_RX.match(paragraphs[i]):
            return paragraphs[i], paragraphs[:i] + paragraphs[i + 1 :]
    return None, paragraphs


# How many consecutive paragraphs without a footer hint may sit inside a footer
# before the scan decides it has walked back into the body. An ESP footer
# interleaves lines carrying no hint of their own, such as a company name or a
# logo caption, between the address block and the unsubscribe line.
_FOOTER_GAP_TOLERANCE = 1


def _peel_footer(paragraphs: list[str]) -> tuple[str | None, list[str]]:
    """Peel the trailing run of footer paragraphs, if there is one.

    A footer sits at the end. This walks back from the last paragraph and keeps
    going while it is still inside that trailing run, allowing a couple of
    hint-free paragraphs in the middle of it.

    It must stop at the body. The earlier version recorded every match without
    stopping, so it settled on the EARLIEST paragraph carrying a hint and swept
    everything after it away. `_FOOTER_HINT_RX` matches a bare street address,
    the word "unsubscribe", "copyright", or "all rights reserved" anywhere in a
    paragraph, so an email naming "45 Oak Street" in its second paragraph lost
    the rest of its content, and roughly a dozen copywriting checks then graded
    what was left. A street address in the body is normal in exactly the mail
    this tool is pointed at.
    """
    if not paragraphs:
        return None, paragraphs

    # A footer ends the message. When the last paragraph carries no hint, any
    # hint earlier on is body text: a sentence naming a street, or one that says
    # the reader can unsubscribe. Checking this first is what stops a mid-body
    # match from swallowing everything after it.
    if not _FOOTER_HINT_RX.search(paragraphs[-1]):
        return None, paragraphs

    footer_start = len(paragraphs) - 1
    gap = 0
    for i in range(len(paragraphs) - 2, -1, -1):
        if _FOOTER_HINT_RX.search(paragraphs[i]):
            footer_start = i
            gap = 0
            continue
        gap += 1
        if gap > _FOOTER_GAP_TOLERANCE:
            break
    footer = "\n\n".join(paragraphs[footer_start:])
    return footer, paragraphs[:footer_start]


def _peel_signature_with_tail(
    paragraphs: list[str],
) -> tuple[str | None, list[str], list[str]]:
    """Find signoff line. Return (signature, paragraphs_before_signoff,
    tail_after_signoff_absorbed_lines). Caller decides what to do with
    the tail (treat as footer + P.S., or leave alone)."""
    if not paragraphs:
        return None, paragraphs, []
    for i in range(len(paragraphs) - 1, -1, -1):
        p = paragraphs[i]
        head = p.split(",", 1)[0] + ","
        if not (_SIGNOFF_RX.match(head) or _SIGNOFF_RX.match(p)):
            continue
        # Absorb up to 4 trailing short paragraphs (name / title /
        # phone / email-ish lines). Stop on the first long block.
        trailing: list[str] = []
        for j in range(i + 1, min(i + 5, len(paragraphs))):
            if len(paragraphs[j].split()) > 6:
                break
            trailing.append(paragraphs[j])
        sig = "\n".join([p, *trailing]).strip()
        cut = i + 1 + len(trailing)
        return sig, paragraphs[:i], paragraphs[cut:]
    return None, paragraphs, []


def _peel_ps(paragraphs: list[str]) -> tuple[str | None, list[str]]:
    """Walk backward for the first paragraph starting with P.S. — the
    P.S. usually sits between signature and footer, but defensive about
    ordering."""
    for i in range(len(paragraphs) - 1, -1, -1):
        if _PS_RX.match(paragraphs[i]):
            return paragraphs[i], paragraphs[:i] + paragraphs[i + 1 :]
    return None, paragraphs


def _count_words(*texts: str | None) -> int:
    total = 0
    for t in texts:
        if not t:
            continue
        total += len(t.split())
    return total


# ─── Public API ────────────────────────────────────────────────────────


def extract_structured(parsed: ParsedEmail) -> StructuredEmail:
    """Pull preview / greeting / body / CTAs / P.S. / signature / footer
    out of a parsed email. All best-effort; None where not detected."""
    raw_plain = (parsed.plain_text or "").strip() or None
    raw_html = parsed.html or None

    preview_text = _extract_preview_text(raw_html)

    # Build the narrative body from plain text when present (more
    # reliable section boundaries via blank lines); fall back to
    # HTML-derived text. Drop the preview text from the body if it
    # leaked in as a leading line.
    if raw_plain:
        body_text = raw_plain
    elif raw_html:
        body_text = _strip_to_text(raw_html)
    else:
        body_text = ""

    if preview_text and body_text.lstrip().startswith(preview_text):
        body_text = body_text.lstrip()[len(preview_text) :].lstrip()

    paragraphs = _split_paragraphs(body_text)

    # Strip ASCII-art section headers and collect their titles.
    section_headers: list[str] = []
    cleaned: list[str] = []
    for p in paragraphs:
        m = _SECTION_HEADER_RX.match(p)
        if m:
            section_headers.append(m.group(2).strip())
        else:
            cleaned.append(p)
    paragraphs = cleaned

    greeting, paragraphs = _peel_greeting(paragraphs)
    signature, paragraphs, tail_after_signature = _peel_signature_with_tail(paragraphs)

    # When we found a signature, everything past it is tail content:
    # split into P.S. (paragraph starting with P.S.) and footer (rest).
    # Otherwise fall back to keyword-based footer + P.S. peel from what's left.
    if signature is not None:
        ps = next((p for p in tail_after_signature if _PS_RX.match(p)), None)
        footer_parts = [p for p in tail_after_signature if p is not ps]
        footer = "\n\n".join(footer_parts).strip() or None
    else:
        footer, paragraphs = _peel_footer(paragraphs)
        ps, paragraphs = _peel_ps(paragraphs)

    cta_blocks = _extract_cta_blocks(raw_html)

    return StructuredEmail(
        subject=parsed.subject,
        preview_text=preview_text,
        greeting=greeting,
        body_blocks=paragraphs,
        section_headers=section_headers,
        cta_blocks=cta_blocks,
        ps=ps,
        signature=signature,
        footer=footer,
        word_count=_count_words(
            parsed.subject,
            preview_text,
            greeting,
            *paragraphs,
            ps,
            signature,
        ),
        raw_html=raw_html,
        raw_plain=raw_plain,
    )
