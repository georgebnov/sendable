"""Scan inline style attrs + <style> blocks for hidden-text salting patterns.

Pattern set from Cisco Talos 2024-2025 hidden-text-salting disclosures.

Content-aware severity:
- Hidden element whose text contains instruction-verb keywords (prompt
  injection) OR exceeds ~300 chars of real content → CRITICAL.
- Otherwise (short hidden text with no instruction verbs — classic ESP
  preheader) → HIGH. Still worth flagging; not a deal-breaker.
- Any hit inside a <style> block is always treated as CRITICAL (rare in
  legit mail and usually sophisticated).
"""

from __future__ import annotations

import re

from ... import esp
from ...htmltree import parse_html
from ...parse import ParsedEmail
from ...report import Finding
from ...severity import Severity

_PATTERNS = [
    (r"display\s*:\s*none", "display:none"),
    (r"visibility\s*:\s*hidden", "visibility:hidden"),
    (r"opacity\s*:\s*0(?:\.0+)?\b", "opacity:0"),
    (r"font-size\s*:\s*0(?:px|pt|em|rem)?\b", "font-size:0"),
    (r"mso-hide\s*:\s*all", "mso-hide:all"),
    (r"text-indent\s*:\s*-\d{3,}px", "text-indent:-9999px"),
    (r"left\s*:\s*-\d{3,}px", "off-screen-left"),
    (r"top\s*:\s*-\d{3,}px", "off-screen-top"),
]
_COMPILED = [(re.compile(p, re.IGNORECASE), name) for p, name in _PATTERNS]

# Instruction verbs common in prompt-injection payloads. Narrow list is fine
# for PoC — legit preheaders are unlikely to contain any of these.
# Prompt-injection phrasing, not single words.
#
# The earlier version matched any of "ignore", "forget", "previous",
# "instructions", "you are", or "act as" on its own. A preheader is hidden text
# by design, so every ESP puts one in a display:none span, and ordinary preheader
# copy tripped it: "Don't forget: sale ends Sunday", "You are invited to our open
# house", "Please ignore if you already registered", "Assembly instructions
# inside". Each became CRITICAL, which is a hard gate, so a clean campaign scored
# NO_GO and the sender was told their email contained a prompt-injection attack.
#
# Injection text addresses a model and tells it to disregard what it was told.
# That takes a verb AND an object, which is what these patterns require.
_INSTRUCTION_VERBS = re.compile(
    r"""
    # An imperative to disregard earlier instructions.
      \b(?:ignore|disregard|forget|override|bypass)\s+
      (?:(?:all|any|the|your|these|previous|prior|above|earlier|other)\s+)*
      (?:instructions?|prompts?|rules?|directions?|guidelines?|context)
    # Naming the model's own configuration.
    | \bsystem\s+prompt\b
    # Role reassignment.
    | \byou\s+are\s+now\b
    | \bact\s+as\s+(?:a|an|the)\s+\w+
    # Supplying replacement instructions.
    | \b(?:new|updated|revised)\s+instructions?\b
    | \bdo\s+not\s+(?:follow|obey)\s+(?:the\s+)?(?:previous|prior|above|earlier)\b
    # Telling a classifier what verdict to reach.
    | \b(?:approve|classify|mark|treat)\s+(?:this|the)\s+(?:message|email|mail)\b
      [^.]{0,40}?\bas\s+(?:safe|legitimate|trusted|not\s+spam)
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Whitespace + invisible + filler characters. ESP preheader "spacers" use
# thousands of these to pad inbox preview width; we strip them before
# measuring real content length.
_NOISE_CHARS = re.compile(
    r"[\s\u00AD\u034F\u200B-\u200F\u2007\u2028-\u202F\u205F\u2060\u2064\u2066-\u206F\uFEFF]"
)

_BENIGN_MAX_LEN = 300

# For <style>-block rules: flatten @media / @supports / @keyframes wrappers
# so inner rules parse as top-level. Leaving the trailing `}` is harmless
# — the rule regex requires a selector before the opening brace.
_AT_RULE_OPEN_RX = re.compile(
    r"@(?:media|supports|document|keyframes|page|-\w+-keyframes)[^{]*\{",
    re.IGNORECASE,
)

# Match one CSS rule: `selector { body-without-nested-braces }`.
_CSS_RULE_RX = re.compile(r"([^{}]+)\{([^{}]*?)\}", re.DOTALL)


def _classify_hidden(text: str) -> str:
    """Return 'adversarial' if the text looks like prompt injection or is long, else 'benign'."""
    if _INSTRUCTION_VERBS.search(text):
        return "adversarial"
    real_len = len(_NOISE_CHARS.sub("", text))
    if real_len > _BENIGN_MAX_LEN:
        return "adversarial"
    return "benign"


def _iter_hidden_rules(css: str):
    """Yield (selector, matched_pattern_names) for every CSS rule in `css`
    whose property block contains a hidden-style pattern. Flattens @media /
    @supports / @keyframes wrappers via _AT_RULE_OPEN_RX."""
    flat = _AT_RULE_OPEN_RX.sub("", css)
    for m in _CSS_RULE_RX.finditer(flat):
        selector = m.group(1).strip()
        body = m.group(2)
        if not selector or selector.startswith("@"):
            continue
        matched = [name for rx, name in _COMPILED if rx.search(body)]
        if matched:
            yield selector, matched


def _selector_target_text(soup, selector_list: str) -> str:
    """Concatenate the text of every element in `soup` that matches any
    selector in the comma-separated `selector_list`. Returns '' if no
    match or if the selector is unparseable."""
    parts: list[str] = []
    for sel in selector_list.split(","):
        sel = sel.strip()
        if not sel:
            continue
        try:
            for el in soup.select(sel):
                t = el.get_text(separator=" ", strip=True)
                if t:
                    parts.append(t)
        except Exception:
            # Selector we can't parse (complex pseudo-class, etc.). Err on the
            # side of not-adversarial — over-flagging was the motivation for
            # this layer in the first place.
            pass
    return " ".join(parts)


async def run(email: ParsedEmail) -> list[Finding]:
    if email.html is None:
        return []

    soup = parse_html(email.html)
    hits: list[dict] = []

    for el in soup.find_all(style=True):
        style = el.get("style", "") or ""
        matched = [name for rx, name in _COMPILED if rx.search(style)]
        if not matched:
            continue
        element_text = el.get_text(separator=" ", strip=True)
        # Skip elements with no content-bearing text: spacer <td>s, tracking
        # <img>s, empty structural hides. A hidden-style that isn't hiding any
        # actual content isn't doing anything adversarial or otherwise worth
        # flagging. "Content-touching or not" is the useful axis.
        if not _NOISE_CHARS.sub("", element_text):
            continue
        classification = _classify_hidden(element_text)
        text_preview = element_text[:80] + ("…" if len(element_text) > 80 else "")
        for name in matched:
            hits.append(
                {
                    "pattern": name,
                    "tag": el.name,
                    "where": "style_attr",
                    "class": classification,
                    "text_preview": text_preview,
                }
            )

    for style_tag in soup.find_all("style"):
        css = style_tag.string or ""
        if not css:
            continue
        for selector, patterns in _iter_hidden_rules(css):
            target_text = _selector_target_text(soup, selector)
            if not target_text:
                # Rule targets no content in the body (dead CSS, @keyframes
                # noise, structural-only selectors). Nothing is actually
                # being hidden → no hit.
                continue
            classification = _classify_hidden(target_text)
            text_preview = target_text[:80] + ("…" if len(target_text) > 80 else "")
            for name in patterns:
                hits.append(
                    {
                        "pattern": name,
                        "where": "style_block",
                        "selector": selector[:80],
                        "class": classification,
                        "text_preview": text_preview,
                    }
                )

    if hits:
        any_adversarial = any(h.get("class") == "adversarial" for h in hits)
        # Adversarial hits never get demoted — instruction-verb / long
        # hidden text is a real prompt-injection signal regardless of who
        # injected it.
        detected = None if any_adversarial else esp.detect(email)
        # Narrowed profile rather than a bool, so chrome.name below type-checks.
        chrome = (
            detected
            if (
                detected is not None
                and detected.is_high_confidence()
                and all(h.get("class") == "benign" for h in hits)
            )
            else None
        )
        if chrome is not None:
            severity = Severity.INFO
            source = "esp_template"
            message = (
                f"Hidden-text patterns detected ({len(hits)} hit(s)) but match "
                f"{chrome.name} template chrome (preview-text / footer). "
                f"Not user content: clear the preview-text field in your "
                f"{chrome.name} composer to remove."
            )
        else:
            severity = Severity.CRITICAL if any_adversarial else Severity.HIGH
            source = "user_content"
            message = (
                f"Hidden-text patterns detected ({len(hits)} hit(s); "
                f"adversarial={any_adversarial})."
            )
        return [
            Finding(
                check="content.hidden_css_salting",
                severity=severity,
                passed=False,
                message=message,
                details={"hits": hits[:20], "esp": detected.name if detected else None},
                source=source,
            )
        ]
    return [
        Finding(
            check="content.hidden_css_salting",
            severity=Severity.INFO,
            passed=True,
            message="No hidden-text salting patterns detected.",
        )
    ]
