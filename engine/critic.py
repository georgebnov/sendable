"""Deterministic copy heuristics. No model call.

Each function takes plain text and returns a list of `Finding`. The audit
runner reaches them through `engine/copywriting/heuristics.py`, which maps
the legacy `copygen.` check prefix onto `copywriting.`.

Checks:
- Subject shape per variant: length, word count, Title Case, ALL CAPS,
  "!" and "?" counts, a "Re:" or "Fwd:" prefix, the word "newsletter",
  emoji count, and a "$" opener.
- Spam-trigger substring scan over subject, preview text, and body. The
  phrases load from `engine/context/spam_triggers.md`.
- Compound signal: how many distinct promotional categories the email hits.
  3 categories is MEDIUM, 4 is HIGH, 5 is CRITICAL. Stacked signals move
  the filter, not any single word.
- Body word count against a length target.
- Link count and destination sanity. A drive.google.com or docs.google.com
  link is HIGH.
- The word "newsletter" in the body.
- Emoji in the subject or body.
"""

from __future__ import annotations

import re
from pathlib import Path

from engine.report import Finding
from engine.severity import Severity


_SPAM_TRIGGERS_PATH = Path(__file__).resolve().parent / "context" / "spam_triggers.md"

_LENGTH_HINT_CAPS = {
    "short": 200,
    "medium": 300,
    "long": 450,
}
_ABSOLUTE_BODY_CEILING = 300

_URL_RX = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
_DRIVE_HOST_RX = re.compile(r"(drive|docs)\.google\.com", re.IGNORECASE)
_EMOJI_RX = re.compile(
    "["
    "\U0001F300-\U0001FAFF"  # symbols + emoji blocks
    "\U00002600-\U000027BF"  # misc symbols + dingbats
    "\U0001F000-\U0001F9FF"  # mahjong through symbols & pictographs
    "\U0001FA70-\U0001FAFF"  # more symbols
    "\U00002700-\U000027BF"  # dingbats
    "]",
    re.UNICODE,
)
_NEWSLETTER_RX = re.compile(r"\bnewsletter\b", re.IGNORECASE)
_LOGO_TOKEN_RX = re.compile(r"(\{logo\}|<img|<logo>|<table|<div)", re.IGNORECASE)


def _load_trigger_map() -> dict[str, list[str]]:
    """Parse spam_triggers.md → {category: [phrase, phrase, ...]}.

    Category headers look like `# ─── label ───`. Lines that start with `#`
    but don't contain `─` (box-drawing dash) are treated as free-form
    comments and do not change the current category. Non-blank, non-comment
    lines are phrases belonging to the current category.
    """
    result: dict[str, list[str]] = {}
    current = "uncategorised"
    if not _SPAM_TRIGGERS_PATH.exists():
        return result
    for raw_line in _SPAM_TRIGGERS_PATH.read_text().splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            if "─" not in stripped:
                continue  # regular comment, skip
            label = stripped.lstrip("#").strip().strip("─").strip()
            if label:
                current = label.lower()
            continue
        result.setdefault(current, []).append(stripped.lower())
    return result


def _check_subjects(subjects: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for i, subj in enumerate(subjects):
        subj = subj or ""
        issues: list[tuple[Severity, str]] = []

        if len(subj) > 50:
            issues.append((Severity.MEDIUM, f"subject is {len(subj)} chars (>50)"))
        words = subj.split()
        if len(words) > 8:
            issues.append((Severity.LOW, f"subject is {len(words)} words (>8)"))

        alpha_words = [w for w in words if any(c.isalpha() for c in w)]
        if alpha_words:
            title_case = sum(1 for w in alpha_words if w[0].isupper() and not w.isupper())
            if title_case / len(alpha_words) >= 0.5 and len(alpha_words) >= 3:
                issues.append((Severity.MEDIUM, "subject is Title Case (prefer sentence case)"))

            all_caps = sum(1 for w in alpha_words if len(w) > 1 and w.isupper())
            if all_caps / len(alpha_words) > 0.3:
                issues.append((Severity.HIGH, "subject uses ALL-CAPS words"))

        if subj.count("!") > 1:
            issues.append((Severity.MEDIUM, "multiple '!' in subject"))
        if subj.count("?") > 1:
            issues.append((Severity.LOW, "multiple '?' in subject"))

        if re.match(r"^\s*(re|fwd|fw)\s*:", subj, re.IGNORECASE):
            issues.append((Severity.HIGH, "subject starts with 'Re:' / 'Fwd:' (deceptive)"))

        if _NEWSLETTER_RX.search(subj):
            issues.append((Severity.LOW, "subject contains 'newsletter' (-18.7% open rate)"))

        if _EMOJI_RX.search(subj):
            count = len(_EMOJI_RX.findall(subj))
            if count > 1:
                issues.append((Severity.MEDIUM, f"subject contains {count} emoji (>1)"))

        leading = subj.lstrip()
        if leading.startswith("$") or re.match(r"^\$?\s*\d+[\d,]*\s*(off|save|\$|%)", leading, re.IGNORECASE):
            issues.append((Severity.MEDIUM, "subject opens with a dollar/price figure"))

        for sev, msg in issues:
            findings.append(Finding(
                check="copygen.subject_heuristics",
                severity=sev,
                passed=False,
                message=f"subject variant {i}: {msg}",
                details={"variant_index": i, "subject": subj},
            ))
    if not findings:
        findings.append(Finding(
            check="copygen.subject_heuristics",
            severity=Severity.INFO,
            passed=True,
            message=f"Subject heuristics passed ({len(subjects)} variant(s)).",
        ))
    return findings


def _check_spam_triggers(
    subject: str, preview: str, body: str, trigger_map: dict[str, list[str]]
) -> tuple[list[Finding], set[str]]:
    """Per-phrase findings + set of categories that fired (for compound score)."""
    findings: list[Finding] = []
    fired_categories: set[str] = set()
    fields = {"subject": subject, "preview": preview, "body": body}
    for category, phrases in trigger_map.items():
        for phrase in phrases:
            for field_name, text in fields.items():
                if phrase in (text or "").lower():
                    fired_categories.add(category)
                    sev = Severity.HIGH if category != "newsletter-word" else Severity.LOW
                    findings.append(Finding(
                        check="copygen.spam_trigger",
                        severity=sev,
                        passed=False,
                        message=f"banned phrase '{phrase}' in {field_name}",
                        details={
                            "phrase": phrase,
                            "category": category,
                            "field": field_name,
                        },
                    ))
    if not findings:
        findings.append(Finding(
            check="copygen.spam_trigger",
            severity=Severity.INFO,
            passed=True,
            message="No spam-trigger phrases detected.",
        ))
    return findings, fired_categories


def _check_compound_signal(fired_categories: set[str]) -> list[Finding]:
    # Formatting / newsletter-word are too noisy to count toward the
    # compound-promotional score on their own.
    promotional = {
        c for c in fired_categories
        if c not in ("formatting", "newsletter-word", "uncategorised")
    }
    n = len(promotional)
    if n <= 2:
        return [Finding(
            check="copygen.compound_signal",
            severity=Severity.INFO,
            passed=True,
            message=f"{n} promotional category(ies) — below the compound-signal threshold.",
            details={"categories": sorted(promotional), "count": n},
        )]
    if n == 3:
        sev = Severity.MEDIUM
    elif n == 4:
        sev = Severity.HIGH
    else:
        sev = Severity.CRITICAL
    return [Finding(
        check="copygen.compound_signal",
        severity=sev,
        passed=False,
        message=f"{n} promotional categories fired simultaneously: {sorted(promotional)}",
        details={"categories": sorted(promotional), "count": n},
    )]


def _check_body_length(body: str, length_hint: str) -> list[Finding]:
    word_count = len((body or "").split())
    cap = _LENGTH_HINT_CAPS.get(length_hint, 200)
    findings: list[Finding] = []
    if word_count > cap + (cap // 2):
        findings.append(Finding(
            check="copygen.body_length",
            severity=Severity.MEDIUM,
            passed=False,
            message=f"body is {word_count} words (hint '{length_hint}' cap {cap})",
            details={"word_count": word_count, "cap": cap, "length_hint": length_hint},
        ))
    if length_hint == "short" and word_count > _ABSOLUTE_BODY_CEILING:
        findings.append(Finding(
            check="copygen.body_length",
            severity=Severity.HIGH,
            passed=False,
            message=f"body is {word_count} words (>300 absolute ceiling for short length)",
            details={"word_count": word_count},
        ))
    if not findings:
        findings.append(Finding(
            check="copygen.body_length",
            severity=Severity.INFO,
            passed=True,
            message=f"Body length OK ({word_count} words, hint '{length_hint}' cap {cap}).",
            details={"word_count": word_count, "cap": cap, "length_hint": length_hint},
        ))
    return findings


def _check_links(body: str) -> list[Finding]:
    findings: list[Finding] = []
    urls = _URL_RX.findall(body or "")
    word_count = len((body or "").split())
    # Ratio rule: ~1 link per 125 words for newsletter bodies. Floor at 2
    # so short drafts can carry a CTA + an unsubscribe link without
    # tripping the check. Modern filters care about per-word link density,
    # not an absolute cap.
    link_budget = max(2, word_count // 125)
    if len(urls) > link_budget:
        findings.append(Finding(
            check="copygen.link_count",
            severity=Severity.MEDIUM,
            passed=False,
            message=(
                f"body contains {len(urls)} URLs across {word_count} words "
                f"(budget {link_budget} = max(2, words/125))"
            ),
            details={
                "count": len(urls),
                "urls": urls[:5],
                "word_count": word_count,
                "link_budget": link_budget,
            },
        ))
    has_drive = False
    for url in urls:
        if _DRIVE_HOST_RX.search(url):
            has_drive = True
            findings.append(Finding(
                check="copygen.drive_link",
                severity=Severity.HIGH,
                passed=False,
                message=f"body contains a Google Drive/Docs link: {url}",
                details={"url": url},
            ))
    if not any(f.check == "copygen.link_count" for f in findings):
        findings.append(Finding(
            check="copygen.link_count",
            severity=Severity.INFO,
            passed=True,
            message=(
                f"Link count OK ({len(urls)} URL(s) across {word_count} words, "
                f"budget {link_budget})."
            ),
            details={
                "count": len(urls),
                "word_count": word_count,
                "link_budget": link_budget,
            },
        ))
    if not has_drive:
        findings.append(Finding(
            check="copygen.drive_link",
            severity=Severity.INFO,
            passed=True,
            message="No Google Drive / Docs links.",
        ))
    return findings


def _check_body_shouting(body: str) -> list[Finding]:
    """Flag body lines that shout (ALL-CAPS runs) or stack exclamation marks.

    Triggers:
     - Any body line where >= 50% of NON-ACRONYM alpha words are ALL-CAPS
       (line must have ≥ 3 non-acronym alpha words) → MEDIUM.
     - Any body line containing 3+ consecutive ALL-CAPS NON-ACRONYM words
       anywhere within it ("AND BUY THIS COURSE!" inside a longer sentence)
       → MEDIUM.
     - Any body line with `!!` or more → MEDIUM.
     - Total `!` count in body > 3 → LOW.

    Acronym carve-out: tokens that are ALL-CAPS AND ≤ 4 chars are treated
    as acronyms (ATSC, PSIP, FCC, NBC, ROI), not shouting. Otherwise table-
    header rows full of technical acronyms get mis-flagged as shouting.
    """
    findings: list[Finding] = []
    body = body or ""
    shouting_lines: list[str] = []
    multi_bang_lines: list[str] = []

    def _is_acronym(w: str) -> bool:
        # Short all-caps tokens like ATSC, PSIP, FCC, ROI, AI, IP, KPI.
        return len(w) <= 4 and w.isupper() and any(c.isalpha() for c in w)

    def _is_shouting_word(w: str) -> bool:
        # Real shouting words are ≥ 5 chars (LIMITED, FREE, URGENT, OFFER).
        return len(w) >= 5 and w.isupper() and any(c.isalpha() for c in w)

    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "!!" in line:
            multi_bang_lines.append(line[:80])
        words = line.split()
        alpha_words = [w for w in words if any(c.isalpha() for c in w)]
        # Drop acronyms from BOTH numerator and denominator so a line full
        # of acronyms doesn't count toward shouting at all.
        non_acronym_alpha = [w for w in alpha_words if not _is_acronym(w)]
        shouting_words = [w for w in non_acronym_alpha if _is_shouting_word(w)]
        if len(non_acronym_alpha) >= 3 and shouting_words:
            if len(shouting_words) / len(non_acronym_alpha) >= 0.5:
                shouting_lines.append(line[:80])
                continue
        # Detect inline run of 3+ consecutive ALL-CAPS NON-ACRONYM words.
        run = 0
        for w in words:
            if _is_shouting_word(w):
                run += 1
                if run >= 3:
                    shouting_lines.append(line[:80])
                    break
            else:
                run = 0

    if shouting_lines:
        findings.append(Finding(
            check="copygen.body_shouting",
            severity=Severity.MEDIUM,
            passed=False,
            message=f"body contains ALL-CAPS shouting ({len(shouting_lines)} line(s))",
            details={"lines": shouting_lines[:5], "count": len(shouting_lines)},
        ))
    if multi_bang_lines:
        findings.append(Finding(
            check="copygen.body_shouting",
            severity=Severity.MEDIUM,
            passed=False,
            message=f"body contains lines with '!!' or more ({len(multi_bang_lines)} line(s))",
            details={"lines": multi_bang_lines[:5], "count": len(multi_bang_lines)},
        ))
    total_bangs = body.count("!")
    if total_bangs > 3:
        findings.append(Finding(
            check="copygen.body_shouting",
            severity=Severity.LOW,
            passed=False,
            message=f"body contains {total_bangs} exclamation marks (>3)",
            details={"count": total_bangs},
        ))
    if not findings:
        findings.append(Finding(
            check="copygen.body_shouting",
            severity=Severity.INFO,
            passed=True,
            message="No ALL-CAPS shouting or exclamation stacking in body.",
        ))
    return findings


def _check_body_newsletter_word(body: str) -> list[Finding]:
    if _NEWSLETTER_RX.search(body or ""):
        return [Finding(
            check="copygen.body_newsletter_word",
            severity=Severity.LOW,
            passed=False,
            message="body contains 'newsletter' (Zippia -18.7% open-rate signal)",
        )]
    return [Finding(
        check="copygen.body_newsletter_word",
        severity=Severity.INFO,
        passed=True,
        message="Body does not contain the word 'newsletter'.",
    )]


def _check_body_emoji(subject: str, body: str) -> list[Finding]:
    total = len(_EMOJI_RX.findall(subject or "")) + len(_EMOJI_RX.findall(body or ""))
    if total > 1:
        return [Finding(
            check="copygen.emoji_count",
            severity=Severity.MEDIUM,
            passed=False,
            message=f"subject + body contain {total} emoji (>1 total)",
            details={"count": total},
        )]
    return [Finding(
        check="copygen.emoji_count",
        severity=Severity.INFO,
        passed=True,
        message=f"Emoji count OK ({total} total across subject + body).",
        details={"count": total},
    )]
